package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/kailun2047/slowmo/instrumentation"
	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	buildDir = "/tmp/slowmo-builds"
)

func startInstrumentation(bpfProg, targetPath string) (*instrumentation.Instrumentor, *instrumentation.EventReader) {
	interpreter := instrumentation.NewELFInterpreter(targetPath)

	runtimeSchedAddr := interpreter.GetGlobalVariableAddr("runtime.sched")
	allpSliceAddr := interpreter.GetGlobalVariableAddr("runtime.allp")
	waitReasonStringsAddr := interpreter.GetGlobalVariableAddr("runtime.waitReasonStrings")
	instrumentor := instrumentation.NewInstrumentor(
		interpreter,
		bpfProg,
		targetPath,
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[uint64]{
			NameInBPFProg: "runtime_sched_addr",
			Value:         runtimeSchedAddr,
		}),
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[uint64]{
			NameInBPFProg: "allp_slice_addr",
			Value:         allpSliceAddr,
		}),
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[uint64]{
			NameInBPFProg: "waitreason_strings_addr",
			Value:         waitReasonStringsAddr,
		}),
	)

	// Parse go functab and write the parsing result into a map to make it
	// available in ebpf program, so that the ebpf program can perform things
	// like callstack unwinding.
	functabMap := instrumentor.GetMap("go_functab")
	funcTab := interpreter.ParseFuncTab()
	for i, funcInfo := range funcTab {
		// Note that for BPF map of array type, there will be max_entry of
		// key-value pairs upon creation of the map. Therefore manipulation of
		// any KV acts as updating an existing entry.
		err := functabMap.Update(uint32(i), funcInfo, ebpf.UpdateExist)
		if err != nil {
			logging.Logger().Fatalf("error writing function info into go_functab map; key: %d, value %+v, error: %v", i, funcInfo, err)
		}
	}

	/* Capturing key events. */
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "newproc",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_newproc"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "schedule",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_schedule"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "gopark",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_gopark"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "ready",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_goready"},
	})

	/* Inspecting goroutine-storing structures. */
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "newproc",
		AttachOffset: instrumentation.AttachOffsetReturns,
		BpfFns:       []string{"go_runq_status"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "execute",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_execute"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "goready",
		AttachOffset: instrumentation.AttachOffsetReturns,
		BpfFns:       []string{"go_goready_runq_status"},
	})
	// TODO: inspect globrunq when entering runtime.execute.

	/* Helpers. */
	instrumentor.InstrumentPackage(instrumentation.PackageSpec{
		TargetPkg: "main",
		BpfFns:    []string{"delay"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "retake",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"avoid_preempt"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "main",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"get_waitreason_strings"},
	})

	ringbufReader, err := ringbuf.NewReader(instrumentor.GetMap("instrumentor_event"))
	if err != nil {
		logging.Logger().Fatal("Create ring buffer reader: ", err)
	}
	eventReader := instrumentation.NewEventReader(interpreter, ringbufReader)
	eventReader.Start()
	return instrumentor, eventReader
}

type SlowmoServer struct {
	proto.UnimplementedSlowmoServiceServer
	execServerAddr   string
	execTimeLimitSec int
}

func NewSlowmoServer(execServerAddr string, execTimeLimitSec int) proto.SlowmoServiceServer {
	return &SlowmoServer{
		execServerAddr:   execServerAddr,
		execTimeLimitSec: execTimeLimitSec,
	}
}

func (server *SlowmoServer) CompileAndRun(req *proto.CompileAndRunRequest, stream grpc.ServerStreamingServer[proto.CompileAndRunResponse]) (compileAndRunErr error) {
	var (
		internalErr      error
		wg               sync.WaitGroup
		gomaxprocsSentCh = make(chan struct{})
		execStream       grpc.ServerStreamingClient[proto.ExecResponse]
		ctx              = stream.Context()
	)

	logging.Logger().Debug("Received CompileAndRun request")
	defer func() {
		if err := recover(); err != nil {
			internalErr = errors.Join(internalErr, fmt.Errorf("panic detected: %v", err))
		}
		if internalErr != nil {
			compileAndRunErr = fmt.Errorf("%w: unexpected error during CompileAndRun (error: %v, program: %s)", ErrInternalExecution, internalErr, req.GetSource())
		}
	}()

	outName, err := sandboxedBuild(req.GetSource(), *req.GoVersion)
	if err != nil {
		if !errors.Is(err, errCompilation) {
			internalErr = fmt.Errorf("internal error when building the program: %w", err)
		} else {
			errMsg := err.Error()
			stream.Send(&proto.CompileAndRunResponse{
				CompileAndRunOneof: &proto.CompileAndRunResponse_CompileError{
					CompileError: &proto.CompilationError{
						ErrorMessage: &errMsg,
					},
				},
			})
		}
		return
	}
	defer func() {
		err := os.Remove(outName)
		if err != nil {
			logging.Logger().Errorf("Failed to remove temp built output file %s: %v", outName, err)
		}
	}()

	conn, err := grpc.NewClient(server.execServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		internalErr = fmt.Errorf("failed to connect to exec server at %s (error: %w)", server.execServerAddr, err)
		return
	}

	if req.GoVersion == nil {
		compileAndRunErr = fmt.Errorf("missing Go version in request")
		return
	}
	instrumentor, probeEventReader := startInstrumentation(instrumentorProg(*req.GoVersion), outName)
	logging.Logger().Debugf("Instrumentor started for program %s", outName)
	defer instrumentor.Close()

	if server.execTimeLimitSec > 0 {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithDeadline(context.Background(), time.Now().Add(time.Duration(server.execTimeLimitSec)*time.Second))
		defer cancelFunc()
	}
	execClient := proto.NewExecServiceClient(conn)
	execStream, err = execClient.Exec(ctx, &proto.ExecRequest{
		Path: &outName,
	})
	if err != nil {
		internalErr = fmt.Errorf("error requesting exec server at %s (error: %w)", server.execServerAddr, err)
		return
	}
	wg.Add(1)
	go func() {
		defer func() {
			probeEventReader.Close()
			conn.Close()
			wg.Done()
		}()
		for {
			execResp, err := execStream.Recv()
			if errors.Is(err, io.EOF) {
				logging.Logger().Debug("Finished receiving exec response stream")
				return
			}
			if status.Code(err) == codes.DeadlineExceeded {
				// Execution has reached max time limit and the request to
				// downstream exec server is cancelled.
				errMsg := "execution time exceeds limit"
				logging.Logger().Warn(errMsg)
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_RuntimeResult{
						RuntimeResult: &proto.RuntimeResult{
							ErrorMessage: &errMsg,
						},
					},
				})
				return
			}
			if err != nil {
				internalErr = fmt.Errorf("error receiving exec response: %w", err)
				return
			}
			if execResp.GetGomaxprocs() != 0 {
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_Gomaxprocs{
						Gomaxprocs: execResp.GetGomaxprocs(),
					},
				})
				close(gomaxprocsSentCh)
			} else if execResp.GetRuntimeOutput() != nil {
				output := execResp.GetRuntimeOutput().GetOutput()
				if strings.Contains(output, outName) {
					output = strings.ReplaceAll(output, outName, "main")
					execResp.GetRuntimeOutput().Output = &output
				}
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_RuntimeOutput{
						RuntimeOutput: execResp.GetRuntimeOutput(),
					},
				})
			} else if execResp.GetRuntimeResult() != nil {
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_RuntimeResult{
						RuntimeResult: execResp.GetRuntimeResult(),
					},
				})
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Synchronize to make sure gomaxprocs is the first stream message sent.
		<-gomaxprocsSentCh
		for event := range probeEventReader.ProbeEventCh {
			stream.Send(&proto.CompileAndRunResponse{
				CompileAndRunOneof: &proto.CompileAndRunResponse_RunEvent{
					RunEvent: event,
				},
			})
		}
	}()

	wg.Wait()
	logging.Logger().Debug("Finished serving CompileAndRun request")
	return
}

var (
	errCompilation = fmt.Errorf("")
)

type compileError struct {
	errMsg string
}

func (ce compileError) Error() string {
	return ce.errMsg
}

func (ce compileError) Is(target error) bool {
	return target == errCompilation
}

func sandboxedBuild(source, goVersion string) (string, error) {
	tempFile, err := os.CreateTemp(buildDir, "target-*.go")
	if err != nil {
		logging.Logger().Errorf("Failed to create temp file: %v", err)
		return "", err
	}
	tempFile.WriteString(source)
	defer func() {
		tempFile.Close()
		err := os.Remove(tempFile.Name())
		if err != nil {
			logging.Logger().Errorf("Failed to remove temp source file %s: %v", tempFile.Name(), err)
		}
	}()

	outName := strings.TrimSuffix(tempFile.Name(), ".go")
	goBuildCmd := exec.Command("/usr/bin/env", goBin(goVersion), "build", "-gcflags=all=-N -l", "-o", outName, tempFile.Name())
	buf := bytes.Buffer{}
	goBuildCmd.Stdout = &buf
	goBuildCmd.Stderr = &buf
	err = goBuildCmd.Run()
	if err != nil {
		return "", compileError{
			errMsg: buf.String(),
		}
	}
	return outName, nil
}

func instrumentorProg(goVersion string) string {
	return fmt.Sprintf("./instrumentor%s.o", goVersion)
}

func goBin(goVersion string) string {
	return fmt.Sprintf("go%s", goVersion)
}
