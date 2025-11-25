package instrumentation

import (
	"bytes"
	"debug/gosym"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
)

var (
	testingProcID0      int64 = 0
	testingProcID1      int64 = 1
	testingMID0         int64 = 0
	testingMID1         int64 = 1
	testingGoID2        int64 = 2
	testingGoID3        int64 = 3
	testingGoID4        int64 = 4
	testingGoID5        int64 = 5
	testingFile1              = "file1"
	testingFile2              = "file2"
	testingFile3              = "file3"
	testingFile4              = "file4"
	testingFileSchedule       = "proc.go"
	testingLine1        int32 = 1
	testingLine2        int32 = 2
	testingLine3        int32 = 3
	testingLine4        int32 = 4
	testingLineSchedule int32 = 5
	testingFunc1              = "func1"
	testingFunc2              = "func2"
	testingFunc3              = "func3"
	testingFunc4              = "func4"
	testingFuncSchedule       = "runtime.schedule"
)

var cannedPCs = map[uint64]struct {
	fileName string
	line     int
	funcName string
}{
	1: {fileName: testingFile1, line: int(testingLine1), funcName: testingFunc1},
	2: {fileName: testingFile2, line: int(testingLine2), funcName: testingFunc2},
	3: {fileName: testingFile3, line: int(testingLine3), funcName: testingFunc3},
	4: {fileName: testingFile4, line: int(testingLine4), funcName: testingFunc4},
	5: {fileName: testingFileSchedule, line: int(testingLineSchedule), funcName: testingFuncSchedule},
}

type cannedPCInterpreter struct{}

func (c *cannedPCInterpreter) PCToLine(pc uint64) (file string, line int, fn *gosym.Func) {
	canned := cannedPCs[pc]
	return canned.fileName, canned.line, &gosym.Func{Sym: &gosym.Sym{Name: canned.funcName}}
}

type cannedRingbufReader struct {
	cannedRecords []ringbuf.Record
}

func (reader *cannedRingbufReader) Read() (ringbuf.Record, error) {
	if len(reader.cannedRecords) == 0 {
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
	curr := reader.cannedRecords[0]
	reader.cannedRecords = reader.cannedRecords[1:]
	return curr, nil
}

func (reader *cannedRingbufReader) Close() error {
	return nil
}

func TestEventReader(t *testing.T) {
	inputs := []struct {
		subtestName         string
		cannedEvents        []any
		expectedProbeEvents []*proto.ProbeEvent
	}{
		{
			subtestName: "ConcurrentRunqStatusEventsFromDifferentCPUs",
			cannedEvents: []any{
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC:   1,
							GoID: uint64(testingGoID2),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID1,
					Runqhead:    2,
					Runqtail:    4,
					MID:         testingMID1,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC:   3,
							GoID: uint64(testingGoID4),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC:   2,
							GoID: uint64(testingGoID3),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID1,
					Runqhead:    2,
					Runqtail:    4,
					MID:         testingMID1,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 3,
						RunqEntry: runqEntry{
							PC:   4,
							GoID: uint64(testingGoID5),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID1,
					Runqhead:    2,
					Runqtail:    4,
					MID:         testingMID1,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 4,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
			},
			expectedProbeEvents: []*proto.ProbeEvent{
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_RunqStatusEvent{
								RunqStatusEvent: &proto.RunqStatusEvent{
									ProcId: &testingProcID0,
									MId:    &testingMID0,
									RunqEntries: []*proto.RunqEntry{
										{
											GoId: &testingGoID2,
											ExecutionContext: &proto.InterpretedPC{
												File: &testingFile1,
												Line: &testingLine1,
												Func: &testingFunc1,
											},
										},
									},
									Runnext: &proto.RunqEntry{
										GoId: &testingGoID3,
										ExecutionContext: &proto.InterpretedPC{
											File: &testingFile2,
											Line: &testingLine2,
											Func: &testingFunc2,
										},
									},
								},
							},
						},
					},
				},
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_RunqStatusEvent{
								RunqStatusEvent: &proto.RunqStatusEvent{
									ProcId: &testingProcID1,
									MId:    &testingMID1,
									RunqEntries: []*proto.RunqEntry{
										{
											GoId: &testingGoID4,
											ExecutionContext: &proto.InterpretedPC{
												File: &testingFile3,
												Line: &testingLine3,
												Func: &testingFunc3,
											},
										},
										{
											GoId: &testingGoID5,
											ExecutionContext: &proto.InterpretedPC{
												File: &testingFile4,
												Line: &testingLine4,
												Func: &testingFunc4,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			subtestName: "Goready",
			cannedEvents: []any{
				goreadyEvent{
					EType: EVENT_TYPE_GOREADY,
					MID:   testingMID0,
					GoID:  uint64(testingGoID4),
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_GOREADY_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC:   1,
							GoID: uint64(testingGoID3),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_GOREADY_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC:   2,
							GoID: uint64(testingGoID4),
						},
					},
				},
			},
			expectedProbeEvents: []*proto.ProbeEvent{
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_GoreadyEvent{
								GoreadyEvent: &proto.GoreadyEvent{
									MId:  &testingMID0,
									GoId: &testingGoID4,
									Runq: &proto.RunqStatusEvent{
										ProcId: &testingProcID0,
										MId:    &testingMID0,
										RunqEntries: []*proto.RunqEntry{
											{
												GoId: &testingGoID3,
												ExecutionContext: &proto.InterpretedPC{
													File: &testingFile1,
													Line: &testingLine1,
													Func: &testingFunc1,
												},
											},
										},
										Runnext: &proto.RunqEntry{
											GoId: &testingGoID4,
											ExecutionContext: &proto.InterpretedPC{
												File: &testingFile2,
												Line: &testingLine2,
												Func: &testingFunc2,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			subtestName: "ConcurrentExecuteEvents",
			cannedEvents: []any{
				executeEvent{
					EType: EVENT_TYPE_EXECUTE,
					MID:   testingMID1,
					Found: runqEntry{
						PC:   1,
						GoID: uint64(testingGoID2),
					},
					CallerPC: 5,
					ProcID:   testingProcID1,
					NumP:     2,
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC:   3,
							GoID: uint64(testingGoID3),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
				executeEvent{
					EType: EVENT_TYPE_EXECUTE,
					MID:   testingMID0,
					Found: runqEntry{
						PC:   3,
						GoID: uint64(testingGoID3),
					},
					CallerPC: 5,
					ProcID:   testingProcID0,
					NumP:     2,
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    2,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: testingMID0,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID1,
					Runqhead:    1,
					Runqtail:    1,
					MID:         testingMID1,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID1,
					Runqhead:    1,
					Runqtail:    1,
					MID:         testingMID1,
					GroupingMID: testingMID0,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
			},
			expectedProbeEvents: []*proto.ProbeEvent{
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_ExecuteEvent{
								ExecuteEvent: &proto.ExecuteEvent{
									MId: &testingMID1,
									Found: &proto.RunqEntry{
										GoId: &testingGoID2,
										ExecutionContext: &proto.InterpretedPC{
											File: &testingFile1,
											Line: &testingLine1,
											Func: &testingFunc1,
										},
									},
									ProcId: &testingProcID1,
									Runqs: []*proto.RunqStatusEvent{
										{
											ProcId:      &testingProcID0,
											RunqEntries: nil,
											Runnext:     nil,
											MId:         &testingMID0,
										},
										{
											ProcId:      &testingProcID1,
											RunqEntries: nil,
											Runnext:     nil,
											MId:         &testingMID1,
										},
									},
								},
							},
						},
					},
				},
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_ExecuteEvent{
								ExecuteEvent: &proto.ExecuteEvent{
									MId: &testingMID0,
									Found: &proto.RunqEntry{
										GoId: &testingGoID3,
										ExecutionContext: &proto.InterpretedPC{
											File: &testingFile3,
											Line: &testingLine3,
											Func: &testingFunc3,
										},
									},
									ProcId: &testingProcID0,
									Runqs: []*proto.RunqStatusEvent{
										{
											ProcId:      &testingProcID0,
											RunqEntries: nil,
											Runnext:     nil,
											MId:         &testingMID0,
										},
										{
											ProcId:      &testingProcID1,
											RunqEntries: nil,
											Runnext:     nil,
											MId:         &testingMID1,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			subtestName: "ConcurrentExecuteAndRunqStatusEvents",
			cannedEvents: []any{
				executeEvent{
					EType: EVENT_TYPE_EXECUTE,
					MID:   testingMID1,
					Found: runqEntry{
						PC:   1,
						GoID: uint64(testingGoID2),
					},
					CallerPC: 5,
					ProcID:   testingProcID1,
					NumP:     2,
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC:   3,
							GoID: uint64(testingGoID3),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    3,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC:   3,
							GoID: uint64(testingGoID3),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    3,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC:   4,
							GoID: uint64(testingGoID4),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    3,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 3,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID1,
					Runqhead:    1,
					Runqtail:    1,
					MID:         testingMID1,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
			},
			expectedProbeEvents: []*proto.ProbeEvent{
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_RunqStatusEvent{
								RunqStatusEvent: &proto.RunqStatusEvent{
									ProcId: &testingProcID0,
									RunqEntries: []*proto.RunqEntry{
										{
											GoId: &testingGoID3,
											ExecutionContext: &proto.InterpretedPC{
												File: &testingFile3,
												Line: &testingLine3,
												Func: &testingFunc3,
											},
										},
										{
											GoId: &testingGoID4,
											ExecutionContext: &proto.InterpretedPC{
												File: &testingFile4,
												Line: &testingLine4,
												Func: &testingFunc4,
											},
										},
									},
									MId: &testingMID0,
								},
							},
						},
					},
				},
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_ExecuteEvent{
								ExecuteEvent: &proto.ExecuteEvent{
									MId: &testingMID1,
									Found: &proto.RunqEntry{
										GoId: &testingGoID2,
										ExecutionContext: &proto.InterpretedPC{
											File: &testingFile1,
											Line: &testingLine1,
											Func: &testingFunc1,
										},
									},
									ProcId: &testingProcID1,
									Runqs: []*proto.RunqStatusEvent{
										{
											ProcId: &testingProcID0,
											RunqEntries: []*proto.RunqEntry{
												{
													GoId: &testingGoID3,
													ExecutionContext: &proto.InterpretedPC{
														File: &testingFile3,
														Line: &testingLine3,
														Func: &testingFunc3,
													},
												},
												{
													GoId: &testingGoID4,
													ExecutionContext: &proto.InterpretedPC{
														File: &testingFile4,
														Line: &testingLine4,
														Func: &testingFunc4,
													},
												},
											},
											Runnext: nil,
											MId:     &testingMID0,
										},
										{
											ProcId:      &testingProcID1,
											RunqEntries: nil,
											Runnext:     nil,
											MId:         &testingMID1,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			subtestName: "ConcurrentExecuteAndGoreadyEvents",
			cannedEvents: []any{
				executeEvent{
					EType: EVENT_TYPE_EXECUTE,
					MID:   testingMID1,
					Found: runqEntry{
						PC:   1,
						GoID: uint64(testingGoID2),
					},
					CallerPC: 5,
					ProcID:   testingProcID1,
					NumP:     2,
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC:   3,
							GoID: uint64(testingGoID3),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
				goreadyEvent{
					EType: EVENT_TYPE_GOREADY,
					MID:   testingMID0,
					GoID:  uint64(testingGoID4),
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_GOREADY_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC:   3,
							GoID: uint64(testingGoID3),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_GOREADY_RUNQ_STATUS,
					ProcID:      testingProcID0,
					Runqhead:    1,
					Runqtail:    2,
					MID:         testingMID0,
					GroupingMID: -1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 2,
						RunqEntry: runqEntry{
							PC:   4,
							GoID: uint64(testingGoID4),
						},
					},
				},
				runqStatusEvent{
					EType:       EVENT_TYPE_RUNQ_STATUS,
					ProcID:      testingProcID1,
					Runqhead:    1,
					Runqtail:    1,
					MID:         testingMID1,
					GroupingMID: testingMID1,
					indexedRunqEntry: indexedRunqEntry{
						RunqEntryIdx: 1,
						RunqEntry: runqEntry{
							PC: 0,
						},
					},
				},
			},
			expectedProbeEvents: []*proto.ProbeEvent{
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_GoreadyEvent{
								GoreadyEvent: &proto.GoreadyEvent{
									MId:  &testingMID0,
									GoId: &testingGoID4,
									Runq: &proto.RunqStatusEvent{
										ProcId: &testingProcID0,
										RunqEntries: []*proto.RunqEntry{
											{
												GoId: &testingGoID3,
												ExecutionContext: &proto.InterpretedPC{
													File: &testingFile3,
													Line: &testingLine3,
													Func: &testingFunc3,
												},
											},
										},
										Runnext: &proto.RunqEntry{
											GoId: &testingGoID4,
											ExecutionContext: &proto.InterpretedPC{
												File: &testingFile4,
												Line: &testingLine4,
												Func: &testingFunc4,
											},
										},
										MId: &testingMID0,
									},
								},
							},
						},
					},
				},
				{
					ProbeEventOneof: &proto.ProbeEvent_StructureStateEvent{
						StructureStateEvent: &proto.StructureStateEvent{
							StructureStateOneof: &proto.StructureStateEvent_ExecuteEvent{
								ExecuteEvent: &proto.ExecuteEvent{
									MId: &testingMID1,
									Found: &proto.RunqEntry{
										GoId: &testingGoID2,
										ExecutionContext: &proto.InterpretedPC{
											File: &testingFile1,
											Line: &testingLine1,
											Func: &testingFunc1,
										},
									},
									ProcId: &testingProcID1,
									Runqs: []*proto.RunqStatusEvent{
										{
											ProcId: &testingProcID0,
											RunqEntries: []*proto.RunqEntry{
												{
													GoId: &testingGoID3,
													ExecutionContext: &proto.InterpretedPC{
														File: &testingFile3,
														Line: &testingLine3,
														Func: &testingFunc3,
													},
												},
											},
											Runnext: &proto.RunqEntry{
												GoId: &testingGoID4,
												ExecutionContext: &proto.InterpretedPC{
													File: &testingFile4,
													Line: &testingLine4,
													Func: &testingFunc4,
												},
											},
											MId: &testingMID0,
										},
										{
											ProcId:      &testingProcID1,
											RunqEntries: nil,
											Runnext:     nil,
											MId:         &testingMID1,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	logging.InitZapLogger("production")
	byteOrder := determineByteOrder()
	for _, input := range inputs {
		t.Run(input.subtestName, func(t *testing.T) {
			t.Parallel()
			cannedRecords := make([]ringbuf.Record, len(input.cannedEvents))
			buf := &bytes.Buffer{}
			for i, event := range input.cannedEvents {
				binary.Write(buf, byteOrder, event)
				cannedRecords[i] = ringbuf.Record{
					RawSample: make([]byte, buf.Len()),
				}
				copy(cannedRecords[i].RawSample, buf.Bytes())
				buf.Reset()
			}
			interpreter := &cannedPCInterpreter{}
			reader := &cannedRingbufReader{
				cannedRecords: cannedRecords,
			}
			testingEventReader := NewEventReader(interpreter, reader)
			testingEventReader.Start()
			probeEventIdx := 0
			for probeEvent := range testingEventReader.ProbeEventCh {
				if !reflect.DeepEqual(input.expectedProbeEvents[probeEventIdx], probeEvent) {
					t.Errorf("Probe event %d didn't match expectation (\nactual:\n%+v\nexpected:\n%+v\n)", probeEventIdx, probeEvent, input.expectedProbeEvents[probeEventIdx])
				}
				probeEventIdx++
			}
			if probeEventIdx != len(input.expectedProbeEvents) {
				t.Errorf("Incorrect number of received probe events (actual: %d, expected: %d)", probeEventIdx, len(input.expectedProbeEvents))
			}
		})
	}
}
