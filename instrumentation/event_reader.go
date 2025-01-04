package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

/*
Go equivalents of instrumentor events.
*/
type eventType uint64

const (
	EVENT_TYPE_NEWPROC eventType = iota
	EVENT_TYPE_DELAY
	EVENT_TYPE_RUNQ_STATUS
	EVENT_TYPE_RUNQ_STEAL
	EVENT_TYPE_EXECUTE
)

type newprocEvent struct {
	EType       eventType
	PC          uint64
	CreatorGoID uint64
}
type runqStatusEvent struct {
	EType  eventType
	ProcID int64
	callStack
	Runqhead  uint32
	Runqtail  uint32
	LocalRunq [localRunqLen]runqEntry
	Runnext   runqEntry
}
type runqEntry struct {
	PC     uint64
	GoID   uint64
	Status uint64
}

func (entry runqEntry) String() string {
	return fmt.Sprintf("PC: %x, GoID: %d, Status: %d", entry.PC, entry.GoID, entry.Status)
}

type delayEvent struct {
	EType eventType
	PC    uint64
}

type runqStealEvent struct {
	EType          eventType
	StealingProcID int64
	StolenProcID   int64
}

type executeEvent struct {
	EType  eventType
	ProcID int64
	GoID   uint64
	GoPC   uint64
	callStack
}

type callStack struct {
	PC       uint64
	CallerPC uint64
}

type eventWithCallStack interface {
	getPC() uint64
	getCallerPC() uint64
}

func (cs callStack) getPC() uint64 {
	return cs.PC
}

func (cs callStack) getCallerPC() uint64 {
	return cs.CallerPC
}

type EventReader struct {
	interpreter   *ELFInterpreter
	ringbufReader *ringbuf.Reader
	eventCh       chan ringbuf.Record
	byteOrder     binary.ByteOrder
}

func NewEventReader(interpreter *ELFInterpreter, ringbufMap *ebpf.Map) *EventReader {
	ringbufReader, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		log.Fatal("Create ring buffer reader: ", err)
	}
	return &EventReader{
		interpreter:   interpreter,
		ringbufReader: ringbufReader,
		eventCh:       make(chan ringbuf.Record),
		byteOrder:     determineByteOrder(),
	}
}

func (r *EventReader) Close() {
	r.ringbufReader.Close()
}

func (r *EventReader) Start() {
	go func() {
		for {
			r.ringbufReader.SetDeadline(time.Now().Add(1 * time.Second))
			record, err := r.ringbufReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Event reader closed")
					return
				}
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					log.Fatal("Read ring buffer: ", err)
				}
			} else {
				r.eventCh <- record
			}
		}
	}()

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		case record := <-r.eventCh:
			var etype eventType
			bytesReader := bytes.NewReader(record.RawSample)
			err := binary.Read(bytesReader, r.byteOrder, &etype)
			if err != nil {
				log.Fatal("Decode event type: ", err)
			}
			err = r.readEvent(bytesReader, etype)
			if err != nil {
				log.Fatalf("Decode event type %v: %v\n", etype, err)
			}
		}
	}
}

func (r *EventReader) readEvent(readSeeker io.ReadSeeker, etype eventType) error {
	var err error

	_, err = readSeeker.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	switch etype {
	case EVENT_TYPE_NEWPROC:
		var event newprocEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		file, line, fn := r.interpreter.PCToLine(event.PC)
		if fn == nil {
			log.Fatalf("Read newproc event: invalid PC %x", event.PC)
		}
		log.Printf("newproc invoked in goroutine %d (function: %s, file: %s, line: %d)\n", event.CreatorGoID, fn.Name, file, line)
	case EVENT_TYPE_DELAY:
		var event delayEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		_, _, fn := r.interpreter.PCToLine(event.PC)
		if fn == nil {
			log.Fatalf("Read delay event: invalid PC %x", event.PC)
		}
	case EVENT_TYPE_RUNQ_STATUS:
		var event runqStatusEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil || !r.shouldKeepEvent(event) {
			break
		}
		_, _, fn := r.interpreter.PCToLine(event.PC)
		log.Printf("In %s, runq status on processor %d: runq (head %d, tail %d): %+v, runnext: %+v)\n",
			fn.Name, event.ProcID, event.Runqhead, event.Runqtail, event.LocalRunq[event.Runqhead:event.Runqtail], event.Runnext)
	case EVENT_TYPE_RUNQ_STEAL:
		var event runqStealEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		log.Printf("Processor %d steals from processor %d", event.StealingProcID, event.StolenProcID)
	case EVENT_TYPE_EXECUTE:
		var event executeEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil || !r.shouldKeepEvent(event) {
			break
		}
		log.Printf("Executing GoID %d (pc: %x) on processor %d", event.GoID, event.GoPC, event.ProcID)
	default:
		err = fmt.Errorf("unrecognized event type")
	}

	return err
}

func (r *EventReader) shouldKeepEvent(event eventWithCallStack) bool {
	_, _, fn := r.interpreter.PCToLine(event.getPC())
	_, _, callerFn := r.interpreter.PCToLine(event.getCallerPC())
	switch fn.Name {
	case "runtime.runqget":
		return callerFn.Name == "runtime.findRunnable"
	case "runtime.newproc":
		return true
	case "runtime.runqsteal":
		return true
	case "runtime.execute":
		return callerFn.Name == "runtime.schedule"
	default:
		return false
	}
}
