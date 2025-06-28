package instrumentation

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
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
	EVENT_TYPE_GLOBAL_RUNQ_STATUS
	EVENT_TYPE_SEMTABLE_STATUS
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
	Runqhead uint64
	Runqtail uint64
	indexedRunqEntry
}
type indexedRunqEntry struct {
	RunqEntryIdx uint64
	RunqEntry    runqEntry
}
type runqEntry struct {
	PC     uint64
	GoID   uint64
	Status uint64
}

func isEmptyEntry(entry runqEntry) bool {
	return entry.PC == 0
}

func (r *EventReader) interpretAndFmtRunqEntries(entries []runqEntry) string {
	sb := strings.Builder{}
	sb.WriteByte('[')
	for i, entry := range entries {
		sb.WriteByte('(')
		sb.WriteString(r.interpretAndFmtRunqEntry(entry))
		sb.WriteByte(')')
		if i != len(entries)-1 {
			sb.WriteByte(',')
		}
	}
	sb.WriteByte(']')
	return sb.String()
}

func (r *EventReader) interpretAndFmtRunqEntry(entry runqEntry) string {
	if isEmptyEntry(entry) {
		return "nil"
	}
	return fmt.Sprintf("PC: %s, GoID: %d, Status: %d", r.interpretAndFmtPC(entry.PC), entry.GoID, entry.Status)
}

func (r *EventReader) interpretAndFmtPC(pc uint64) string {
	file, line, fn := r.interpreter.PCToLine(pc)
	if fn == nil {
		log.Printf("Cannot interpret PC %x", pc)
		return fmt.Sprintf("%x", pc)
	}
	return fmt.Sprintf("%s (%s:%d)", fn.Name, file, line)
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

type globalRunqStatusEvent struct {
	EType eventType
	callStack
	Size int64
	indexedRunqEntry
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

type semtableStatusEvent struct {
	EType   eventType
	Version uint64
	Sudog   sudog
	IsLast  uint64
}

type sudog struct {
	Goid uint64
	Elem uint64
}

type versionedSemtable struct {
	version uint64
	sudogs  []sudog
}

type EventReader struct {
	interpreter   *ELFInterpreter
	ringbufReader *ringbuf.Reader
	eventCh       chan ringbuf.Record
	byteOrder     binary.ByteOrder
	localRunqs    map[int64][]runqEntry
	globrunq      []runqEntry
	semtable      versionedSemtable
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
		localRunqs:    make(map[int64][]runqEntry),
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
		log.Printf("newproc invoked in GoID: %d (function: %s, file: %s, line: %d)", event.CreatorGoID, fn.Name, file, line)
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
		if _, ok := r.localRunqs[event.ProcID]; !ok {
			r.localRunqs[event.ProcID] = []runqEntry{}
		}
		if event.RunqEntryIdx == uint64(event.Runqtail) {
			log.Printf("In %s, runq status on processor %d: runq (head %d, tail %d): %s, runnext: %s)",
				r.interpretAndFmtPC(event.PC), event.ProcID, event.Runqhead, event.Runqtail, r.interpretAndFmtRunqEntries(r.localRunqs[event.ProcID]), r.interpretAndFmtRunqEntry(event.RunqEntry))
			delete(r.localRunqs, event.ProcID)
		} else {
			r.localRunqs[event.ProcID] = append(r.localRunqs[event.ProcID], event.RunqEntry)
		}
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
		log.Printf("Executing GoID: %d (function: %s) on processor %d",
			event.GoID, r.interpretAndFmtPC(event.GoPC), event.ProcID)
	case EVENT_TYPE_GLOBAL_RUNQ_STATUS:
		var event globalRunqStatusEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		if event.RunqEntryIdx == uint64(event.Size) {
			log.Printf("In %s, global runq status: %s", r.interpretAndFmtPC(event.PC), r.interpretAndFmtRunqEntries(r.globrunq))
			r.globrunq = []runqEntry{}
		} else {
			r.globrunq = append(r.globrunq, event.RunqEntry)
		}
	case EVENT_TYPE_SEMTABLE_STATUS:
		var event semtableStatusEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		if event.Version > r.semtable.version {
			log.Printf("Received semtable status event of newer version %d, resetting semtable", event.Version)
			r.semtable.version = event.Version
			r.semtable.sudogs = []sudog{}
		} else if event.Version < r.semtable.version {
			log.Printf("Received semtable status event of stale version %d, discarding", event.Version)
			break
		}
		if event.IsLast == 1 {
			var semtableSb strings.Builder
			semtableSb.WriteString("[")
			for i, entry := range r.semtable.sudogs {
				semtableSb.WriteString(fmt.Sprintf("GoID %d is waiting on %s (%x)", entry.Goid, r.interpreter.SymByDataElemAddr(entry.Elem), entry.Elem))
				if i < len(r.semtable.sudogs)-1 {
					semtableSb.WriteString(", ")
				}
			}
			semtableSb.WriteString("]")
			log.Printf("Semtable: %s", semtableSb.String())
		} else {
			r.semtable.sudogs = append(r.semtable.sudogs, event.Sudog)
		}
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
