package instrumentation

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/kailun2047/slowmo/proto"
)

/*
Go equivalents of instrumentor events.
*/
type eventType uint64

const (
	EVENT_TYPE_NEWPROC eventType = iota
	EVENT_TYPE_DELAY
	EVENT_TYPE_RUNQ_STATUS
	// EVENT_TYPE_RUNQ_STEAL
	// EVENT_TYPE_EXECUTE
	EVENT_TYPE_GLOBAL_RUNQ_STATUS = iota + 2
	EVENT_TYPE_SEMTABLE_STATUS
	EVENT_TYPE_SCHEDULE
)

type newprocEvent struct {
	EType       eventType
	PC          uint64
	CreatorGoID uint64
	MID         int64
}

type runqStatusEvent struct {
	EType    eventType
	ProcID   int64
	Runqhead uint64
	Runqtail uint64
	indexedRunqEntry
	MID int64
}
type indexedRunqEntry struct {
	RunqEntryIdx uint64
	RunqEntry    runqEntry
}
type runqEntry struct {
	PC   uint64
	GoID uint64
}

func isDummyEntry(entry runqEntry) bool {
	return entry.PC == 0
}

func (r *EventReader) interpretRunqEntries(entries []runqEntry) []*proto.RunqEntry {
	runqEntries := make([]*proto.RunqEntry, len(entries))
	for i, entry := range entries {
		if isDummyEntry(entry) {
			runqEntries[i] = &proto.RunqEntry{}
		} else {
			goId := int64(entry.GoID)
			runqEntries[i] = &proto.RunqEntry{
				GoId:             &goId,
				ExecutionContext: r.interpretPC(entry.PC),
			}
		}
	}
	return runqEntries
}

func (r *EventReader) interpretPC(pc uint64) *proto.InterpretedPC {
	file, line, fn := r.interpreter.PCToLine(pc)
	if fn == nil {
		log.Printf("Cannot interpret PC %x", pc)
		return &proto.InterpretedPC{}
	}
	ln := int32(line)
	return &proto.InterpretedPC{
		File: &file,
		Func: &fn.Name,
		Line: &ln,
	}
}

type delayEvent struct {
	EType eventType
	PC    uint64
	GoID  uint64
	MID   int64
}

type scheduleEvent struct {
	EType          eventType
	MID            int64
	Callstack      [32]uint64
	CallstackDepth int64
	ProcID         int64 // -1 if not applicable
}

type globalRunqStatusEvent struct {
	EType eventType
	Size  int64
	indexedRunqEntry
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
	ProbeEventCh  chan *proto.ProbeEvent
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
		ProbeEventCh:  make(chan *proto.ProbeEvent),
	}
}

// When Close() is called, there's no guarantee that all events which are
// intended to be collected are indeed transmitted. Thus it's the caller's
// responsibility to make sure there won't be any further events to collect
// before calling Close().
func (r *EventReader) Close() {
	r.ringbufReader.Close()
}

func (r *EventReader) Start() {
	go func() {
		defer close(r.eventCh)
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

	go func() {
		defer close(r.ProbeEventCh)
		for record := range r.eventCh {
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
	}()
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
		interpretedPC := r.interpretPC(event.PC)
		if interpretedPC.Func == nil {
			log.Fatalf("Read newproc event: invalid PC %x", event.PC)
		}
		creatorGoId := int64(event.CreatorGoID)
		probeEvent := &proto.ProbeEvent{
			ProbeEventOneof: &proto.ProbeEvent_NotificationEvent{
				NotificationEvent: &proto.NotificationEvent{
					NotificationOneof: &proto.NotificationEvent_NewProcEvent{
						NewProcEvent: &proto.NewProcEvent{
							CreatorGoId: &creatorGoId,
							MId:         &event.MID,
							StartPc:     interpretedPC,
						},
					},
					InvolvedStructures: []*proto.StructureId{
						{
							StructureType: proto.StructureType_LocalRunq,
							MId:           &event.MID,
						},
					},
				},
			},
		}
		log.Printf("Newproc event: %+v", probeEvent)
		r.ProbeEventCh <- probeEvent
	case EVENT_TYPE_DELAY:
		var event delayEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		interpretedPC := r.interpretPC(event.PC)
		if interpretedPC.Func == nil {
			log.Fatalf("Read delay event: invalid PC %x", event.PC)
		}
		goId := int64(event.GoID)
		probeEvent := &proto.ProbeEvent{
			ProbeEventOneof: &proto.ProbeEvent_NotificationEvent{
				NotificationEvent: &proto.NotificationEvent{
					NotificationOneof: &proto.NotificationEvent_DelayEvent{
						DelayEvent: &proto.DelayEvent{
							GoId:      &goId,
							MId:       &event.MID,
							CurrentPc: interpretedPC,
						},
					},
				},
			},
		}
		log.Printf("Delay event: %v", probeEvent)
		r.ProbeEventCh <- probeEvent
	case EVENT_TYPE_SCHEDULE:
		var event scheduleEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		if probeEvent := r.interpretScheduleCallstack(event); probeEvent != nil {
			r.ProbeEventCh <- probeEvent
		}
	case EVENT_TYPE_RUNQ_STATUS:
		var event runqStatusEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		if _, ok := r.localRunqs[event.ProcID]; !ok {
			r.localRunqs[event.ProcID] = []runqEntry{}
		}
		if event.RunqEntryIdx == uint64(event.Runqtail) {
			runnext := r.interpretRunqEntries([]runqEntry{event.RunqEntry})[0]
			probeEvent := &proto.ProbeEvent{
				ProbeEventOneof: &proto.ProbeEvent_RunqStatusEvent{
					RunqStatusEvent: &proto.RunqStatusEvent{
						ProcId:      &event.ProcID,
						RunqEntries: r.interpretRunqEntries(r.localRunqs[event.ProcID]),
						Runnext:     runnext,
					},
				},
			}
			delete(r.localRunqs, event.ProcID)
			log.Printf("Local runq status event: %v", probeEvent)
			r.ProbeEventCh <- probeEvent
		} else {
			r.localRunqs[event.ProcID] = append(r.localRunqs[event.ProcID], event.RunqEntry)
		}
	case EVENT_TYPE_GLOBAL_RUNQ_STATUS:
		var event globalRunqStatusEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		if event.RunqEntryIdx == uint64(event.Size) {
			log.Printf("Global runq status: %v", r.interpretRunqEntries(r.globrunq))
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

func (r *EventReader) interpretScheduleCallstack(event scheduleEvent) (probeEvent *proto.ProbeEvent) {
	callstack := event.Callstack[:event.CallstackDepth]
	interpretedCallstack := make([]*proto.InterpretedPC, len(callstack))
	for i, pc := range callstack {
		interpretedCallstack[i] = r.interpretPC(pc)
	}
	triggerFunc := interpretedCallstack[0].Func
	if triggerFunc == nil || *triggerFunc != "runtime.schedule" {
		log.Fatalf("Invalid trigger func for PC %x", callstack[0])
	}
	log.Printf("%s called for MID %d, callstack: %+v, pc list: %v", *triggerFunc, event.MID, interpretedCallstack, callstack)

	probeEvent = &proto.ProbeEvent{
		ProbeEventOneof: &proto.ProbeEvent_NotificationEvent{
			NotificationEvent: &proto.NotificationEvent{
				NotificationOneof: &proto.NotificationEvent_ScheduleEvent{
					ScheduleEvent: &proto.ScheduleEvent{
						MId:    &event.MID,
						Reason: findScheduleReason(interpretedCallstack),
					},
				},
			},
			// TODO: add involved structures for schedule event.
		},
	}
	if event.ProcID != -1 {
		probeEvent.GetNotificationEvent().GetScheduleEvent().ProcId = &event.ProcID
	}
	return
}

var runtimeFuncToScheduleReason = map[string]proto.ScheduleReason{
	"runtime.goexit": proto.ScheduleReason_GOEXIT,
	"runtime.gopark": proto.ScheduleReason_GOPARK,
	"runtime.mstart": proto.ScheduleReason_MSTART,
}

func findScheduleReason(callstack []*proto.InterpretedPC) proto.ScheduleReason {
	reason := proto.ScheduleReason_OTHER
	for i := 1; i < len(callstack); i++ {
		currFunc := callstack[i].Func
		if r, ok := runtimeFuncToScheduleReason[*currFunc]; ok {
			reason = r
			break
		}
	}
	return reason
}
