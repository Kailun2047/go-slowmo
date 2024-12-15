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
	EVENT_TYPE_RUNTIME_FUNC_RETURN
)

type newprocEvent struct {
	EType       eventType
	PC          uint64
	CreatorGoID uint64
}
type runqUpdateEvent struct {
	EType     eventType
	ProcID    int64
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
	case EVENT_TYPE_RUNTIME_FUNC_RETURN:
		var event runqUpdateEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		log.Printf("runq update detected on processor %d; runq (head %d, tail %d): %+v, runnext: %+v)\n",
			event.ProcID, event.Runqhead, event.Runqtail, event.LocalRunq[event.Runqhead:event.Runqtail], event.Runnext)
	default:
		err = fmt.Errorf("unrecognized event type")
	}

	return err
}
