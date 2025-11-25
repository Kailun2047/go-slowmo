package instrumentation

import (
	"bytes"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/kailun2047/slowmo/logging"
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
	// EVENT_TYPE_SEMTABLE_STATUS
	EVENT_TYPE_SCHEDULE = iota + 3
	EVENT_TYPE_EXECUTE
	EVENT_TYPE_GOPARK
	EVENT_TYPE_GOREADY
	EVENT_TYPE_GOREADY_RUNQ_STATUS
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
	// GroupingMID is set as the id of the triggering M when collecting statuses
	// of multiple runqs, and as a negative number when only collecting status
	// of an individual runq.
	GroupingMID int64
}
type indexedRunqEntry struct {
	RunqEntryIdx uint64
	RunqEntry    runqEntry
}
type runqEntry struct {
	PC   uint64 // 0 if not a real entry (e.g. when representing a nil runnext)
	GoID uint64
}

func (event runqStatusEvent) formLocalRunqKey() string {
	return fmt.Sprintf("%d:%d:%d", event.EType, event.GroupingMID, event.ProcID)
}

func isDummyEntry(entry runqEntry) bool {
	return entry.PC == 0
}

func (r *EventReader) interpretRunqEntries(entries []runqEntry) []*proto.RunqEntry {
	var runqEntries []*proto.RunqEntry
	for _, entry := range entries {
		if interpretedEntry := r.interpretRunqEntry(entry); interpretedEntry != nil {
			runqEntries = append(runqEntries, interpretedEntry)
		}
	}
	return runqEntries
}

func (r *EventReader) interpretRunqEntry(entry runqEntry) *proto.RunqEntry {
	if isDummyEntry(entry) {
		return nil
	}
	goId := int64(entry.GoID)
	return &proto.RunqEntry{
		GoId:             &goId,
		ExecutionContext: r.interpretPC(entry.PC),
	}
}

func (r *EventReader) interpretPC(pc uint64) *proto.InterpretedPC {
	file, line, fn := r.interpreter.PCToLine(pc)
	if fn == nil {
		logging.Logger().Warnf("Cannot interpret PC %x", pc)
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
	Callstack      [8]uint64
	CallstackDepth int64
	ProcID         int64 // -1 if not applicable
}

type globalRunqStatusEvent struct {
	EType eventType
	Size  int64
	indexedRunqEntry
}

type executeEvent struct {
	EType    eventType
	MID      int64
	Found    runqEntry
	CallerPC uint64
	ProcID   int64
	NumP     uint64
}

type executeEventBuffer struct {
	event        executeEvent
	runqStatuses []*proto.RunqStatusEvent
}

func (buf *executeEventBuffer) isCompleted() bool {
	return len(buf.runqStatuses) == int(buf.event.NumP)
}

type goparkEvent struct {
	EType      eventType
	MID        int64
	Parked     runqEntry
	WaitReason [40]byte
}

type goreadyEvent struct {
	EType eventType
	MID   int64
	GoID  uint64
}

type pcInterpreter interface {
	PCToLine(pc uint64) (file string, line int, fn *gosym.Func)
}

type ringbufReadCloser interface {
	Read() (ringbuf.Record, error)
	Close() error
}

type EventReader struct {
	interpreter           pcInterpreter
	ringbufReader         ringbufReadCloser
	eventCh               chan ringbuf.Record
	byteOrder             binary.ByteOrder
	localRunqs            map[string][]runqEntry
	bufferedExecuteEvents map[int64]*executeEventBuffer
	bufferedGoreadyEvents map[int64]*proto.GoreadyEvent
	globrunq              []runqEntry
	ProbeEventCh          chan *proto.ProbeEvent
}

func NewEventReader(interpreter pcInterpreter, ringbufReader ringbufReadCloser) *EventReader {
	return &EventReader{
		interpreter:           interpreter,
		ringbufReader:         ringbufReader,
		eventCh:               make(chan ringbuf.Record),
		byteOrder:             determineByteOrder(),
		localRunqs:            make(map[string][]runqEntry),
		bufferedExecuteEvents: make(map[int64]*executeEventBuffer),
		bufferedGoreadyEvents: make(map[int64]*proto.GoreadyEvent),
		ProbeEventCh:          make(chan *proto.ProbeEvent),
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
			record, err := r.ringbufReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					logging.Logger().Debug("Event reader closed")
					return
				}
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					logging.Logger().Fatal("Read ring buffer: ", err)
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
				logging.Logger().Fatal("Decode event type: ", err)
			}
			err = r.readEvent(bytesReader, etype)
			if err != nil {
				logging.Logger().Fatalf("Decode event type %v: %v", etype, err)
			}
		}
	}()
}

func (r *EventReader) readEvent(readSeeker io.ReadSeeker, etype eventType) error {
	var (
		err        error
		probeEvent *proto.ProbeEvent
	)

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
			logging.Logger().Fatalf("Read newproc event: invalid PC %x", event.PC)
		}
		creatorGoId := int64(event.CreatorGoID)
		probeEvent = &proto.ProbeEvent{
			ProbeEventOneof: &proto.ProbeEvent_NotificationEvent{
				NotificationEvent: &proto.NotificationEvent{
					NotificationOneof: &proto.NotificationEvent_NewProcEvent{
						NewProcEvent: &proto.NewProcEvent{
							CreatorGoId: &creatorGoId,
							MId:         &event.MID,
							StartPc:     interpretedPC,
						},
					},
				},
			},
		}
	case EVENT_TYPE_DELAY:
		var event delayEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		interpretedPC := r.interpretPC(event.PC)
		if interpretedPC.Func == nil {
			logging.Logger().Fatalf("Read delay event: invalid PC %x", event.PC)
		}
		goId := int64(event.GoID)
		probeEvent = &proto.ProbeEvent{
			ProbeEventOneof: &proto.ProbeEvent_DelayEvent{
				DelayEvent: &proto.DelayEvent{
					GoId:      &goId,
					MId:       &event.MID,
					CurrentPc: interpretedPC,
				},
			},
		}
	case EVENT_TYPE_SCHEDULE:
		var event scheduleEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		probeEvent = r.interpretScheduleCallstack(event)
	case EVENT_TYPE_RUNQ_STATUS, EVENT_TYPE_GOREADY_RUNQ_STATUS:
		var event runqStatusEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		localRunqKey := event.formLocalRunqKey()
		if _, ok := r.localRunqs[localRunqKey]; !ok {
			r.localRunqs[localRunqKey] = []runqEntry{}
		}
		if event.RunqEntryIdx == uint64(event.Runqtail) {
			convertedEvent := r.convertRunqStatusEvent(event)
			// Update any existing entry in buffered execute event in case
			// of concurrency.
			for _, buf := range r.bufferedExecuteEvents {
				existingIdx := slices.IndexFunc(buf.runqStatuses, func(runq *proto.RunqStatusEvent) bool {
					return *runq.ProcId == *convertedEvent.ProcId
				})
				if existingIdx != -1 {
					buf.runqStatuses[existingIdx] = convertedEvent
				}
			}

			if event.GroupingMID < 0 {
				if event.EType == EVENT_TYPE_GOREADY_RUNQ_STATUS {
					probeEvent = r.completeGoreadyEvent(event.MID, convertedEvent)
				} else {
					probeEvent = &proto.ProbeEvent{
						ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
							StructureStateEvent: &proto.StructureStateEvent{
								StructureStateOneof: &proto.StructureStateEvent_RunqStatusEvent{
									RunqStatusEvent: convertedEvent,
								},
							},
						},
					}
				}
			} else {
				probeEvent = r.tryCompleteExecuteEvent(event.GroupingMID, convertedEvent)
			}
		} else {
			r.localRunqs[localRunqKey] = append(r.localRunqs[localRunqKey], event.RunqEntry)
		}
	case EVENT_TYPE_GLOBAL_RUNQ_STATUS:
		var event globalRunqStatusEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		if event.RunqEntryIdx == uint64(event.Size) {
			logging.Logger().Debugf("Global runq status: %v", r.interpretRunqEntries(r.globrunq))
			r.globrunq = []runqEntry{}
		} else {
			r.globrunq = append(r.globrunq, event.RunqEntry)
		}
	case EVENT_TYPE_GOPARK:
		var event goparkEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		goID := int64(event.Parked.GoID)
		nullByteIdx := slices.Index(event.WaitReason[:], 0)
		if nullByteIdx == -1 {
			err = fmt.Errorf("null byte not found in wait reason %s", event.WaitReason)
			break
		}
		waitReason := string(event.WaitReason[:nullByteIdx])
		probeEvent = &proto.ProbeEvent{
			ProbeEventOneof: &proto.ProbeEvent_NotificationEvent{
				NotificationEvent: &proto.NotificationEvent{
					NotificationOneof: &proto.NotificationEvent_GoparkEvent{
						GoparkEvent: &proto.GoparkEvent{
							MId: &event.MID,
							Parked: &proto.RunqEntry{
								GoId:             &goID,
								ExecutionContext: r.interpretPC(event.Parked.PC),
							},
							WaitReason: &waitReason,
						},
					},
				},
			},
		}
	case EVENT_TYPE_EXECUTE:
		var event executeEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		interpretedCallerPC := r.interpretPC(event.CallerPC)
		if interpretedCallerPC.Func == nil || *interpretedCallerPC.Func != "runtime.schedule" {
			logging.Logger().Infof("Execute event from non-target callsite (%s), skipping...", *interpretedCallerPC.Func)
			break
		}
		r.bufferedExecuteEvents[event.MID] = &executeEventBuffer{
			event: event,
		}
	case EVENT_TYPE_GOREADY:
		var event goreadyEvent
		err = binary.Read(readSeeker, r.byteOrder, &event)
		if err != nil {
			break
		}
		goId := int64(event.GoID)
		r.bufferedGoreadyEvents[event.MID] = &proto.GoreadyEvent{
			MId:  &event.MID,
			GoId: &goId,
		}
	default:
		err = fmt.Errorf("unrecognized event type")
	}

	if probeEvent != nil {
		logging.Logger().Debugf("Upon receiving event of type %v, probe event created: %+v", etype, probeEvent)
		r.ProbeEventCh <- probeEvent
	}

	return err
}

func (r *EventReader) convertRunqStatusEvent(event runqStatusEvent) *proto.RunqStatusEvent {
	localRunqKey := event.formLocalRunqKey()
	runnext := r.interpretRunqEntry(event.RunqEntry)
	entries := r.interpretRunqEntries(r.localRunqs[localRunqKey])
	convertedEvent := &proto.RunqStatusEvent{
		ProcId:      &event.ProcID,
		RunqEntries: entries,
		Runnext:     runnext,
	}
	if event.MID >= 0 {
		convertedEvent.MId = &event.MID
	}
	delete(r.localRunqs, localRunqKey)
	return convertedEvent
}

func (r *EventReader) tryCompleteExecuteEvent(groupingMID int64, runqStatus *proto.RunqStatusEvent) *proto.ProbeEvent {
	var probeEvent *proto.ProbeEvent

	buf := r.bufferedExecuteEvents[groupingMID]
	if buf == nil {
		logging.Logger().Fatalf("No buffered execute event found for grouping mID %d", groupingMID)
	}
	buf.runqStatuses = append(buf.runqStatuses, runqStatus)
	if buf.isCompleted() {
		event := buf.event
		goId := int64(event.Found.GoID)
		probeEvent = &proto.ProbeEvent{
			ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
				StructureStateEvent: &proto.StructureStateEvent{
					StructureStateOneof: &proto.StructureStateEvent_ExecuteEvent{
						ExecuteEvent: &proto.ExecuteEvent{
							MId: &event.MID,
							Found: &proto.RunqEntry{
								GoId:             &goId,
								ExecutionContext: r.interpretPC(event.Found.PC),
							},
							ProcId: &event.ProcID,
							Runqs:  buf.runqStatuses,
						},
					},
				},
			},
		}
		delete(r.bufferedExecuteEvents, groupingMID)
	}
	return probeEvent
}

func (r *EventReader) completeGoreadyEvent(mID int64, runqStatus *proto.RunqStatusEvent) *proto.ProbeEvent {
	buf := r.bufferedGoreadyEvents[mID]
	if buf == nil {
		logging.Logger().Fatalf("No buffered goready event found for mID %d", mID)
	}
	buf.Runq = runqStatus
	return &proto.ProbeEvent{
		ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
			StructureStateEvent: &proto.StructureStateEvent{
				StructureStateOneof: &proto.StructureStateEvent_GoreadyEvent{
					GoreadyEvent: buf,
				},
			},
		},
	}
}

func (r *EventReader) interpretScheduleCallstack(event scheduleEvent) (probeEvent *proto.ProbeEvent) {
	callstack := event.Callstack[:event.CallstackDepth]
	interpretedCallstack := make([]*proto.InterpretedPC, len(callstack))
	for i, pc := range callstack {
		interpretedCallstack[i] = r.interpretPC(pc)
	}
	triggerFunc := interpretedCallstack[0].Func
	if triggerFunc == nil || *triggerFunc != "runtime.schedule" {
		logging.Logger().Fatalf("Invalid trigger func for PC %x", callstack[0])
	}
	logging.Logger().Debugf("%s called for MID %d, callstack: %+v, pc list: %v", *triggerFunc, event.MID, interpretedCallstack, callstack)

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
		},
	}
	if event.ProcID >= 0 {
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
		if currFunc == nil {
			break
		}
		if r, ok := runtimeFuncToScheduleReason[*currFunc]; ok {
			reason = r
			break
		}
	}
	return reason
}
