package server

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kailun2047/slowmo/instrumentation"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/grpc"
)

const (
	instrumentorProgPath = "./instrumentor.o"

	outputReaderLimit  = 1024
	executionTimeLimit = 10 * time.Second
)

var gomaxprocs = runtime.GOMAXPROCS(-1)

func startInstrumentation(bpfProg, targetPath string) (*instrumentation.Instrumentor, *instrumentation.EventReader) {
	flag.Parse()

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
			log.Fatalf("error writing function info into go_functab map; key: %d, value %+v, error: %v", i, funcInfo, err)
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

	eventReader := instrumentation.NewEventReader(interpreter, instrumentor.GetMap("instrumentor_event"))
	eventReader.Start()
	return instrumentor, eventReader
}

type SlowmoServer struct {
	proto.UnimplementedSlowmoServiceServer
}

func NewSlowmoServer() *SlowmoServer {
	return &SlowmoServer{}
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

func (server *SlowmoServer) CompileAndRun(req *proto.CompileAndRunRequest, stream grpc.ServerStreamingServer[proto.CompileAndRunResponse]) (compileAndRunErr error) {
	log.Println("Received CompileAndRun request")
	var (
		internalErr error
		wg          sync.WaitGroup
	)

	defer func() {
		if err := recover(); err != nil {
			internalErr = errors.Join(internalErr, fmt.Errorf("panic detected: %v", err))
		}
		if internalErr != nil {
			log.Printf("unexpected error during CompileAndRun (error: %v, program: %s)", internalErr, req.GetSource())
			compileAndRunErr = internalErr
		}
	}()

	outName, err := sandboxedBuild(req.GetSource())
	if err != nil {
		if !errors.Is(err, errCompilation) {
			internalErr = fmt.Errorf("internal error when building the program")
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
	} else {
		defer func() {
			err := os.Remove(outName)
			if err != nil {
				log.Printf("Failed to remove temp built output file %s: %v", outName, err)
			}
		}()
		stream.Send(&proto.CompileAndRunResponse{
			CompileAndRunOneof: &proto.CompileAndRunResponse_Gomaxprocs{
				Gomaxprocs: int32(gomaxprocs),
			},
		})
		instrumentor, probeEventReader := startInstrumentation(instrumentorProgPath, outName)
		log.Printf("Instrumentor started for program %s", outName)
		defer instrumentor.Close()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for event := range probeEventReader.ProbeEventCh {
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_RunEvent{
						RunEvent: event,
					},
				})
			}
		}()

		pipeReader, pipeWriter := io.Pipe()
		runTargetCmd, err := sandboxedRun(outName, pipeWriter)
		if err != nil {
			internalErr = fmt.Errorf("internal error when starting the program: %w", err)
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var (
					n       int
					readErr error
					buf     []byte = make([]byte, outputReaderLimit)
				)
				for readErr == nil {
					n, readErr = pipeReader.Read(buf)
					if n > 0 {
						out := string(buf)
						stream.Send(&proto.CompileAndRunResponse{
							CompileAndRunOneof: &proto.CompileAndRunResponse_RuntimeOutput{
								RuntimeOutput: &proto.RuntimeOutput{
									Output: &out,
								},
							},
						})
					}
				}
				if !errors.Is(readErr, io.EOF) {
					log.Printf("Received unexpected error from pipe reader: %v", readErr)
				}
			}()

			runTargetCmd.Wait()
			pipeWriter.Close()
			log.Printf("Program %s exited", outName)
		}
		probeEventReader.Close()
	}

	wg.Wait()
	log.Println("Finished serving CompileAndRun request")
	return
}

func sandboxedBuild(source string) (string, error) {
	tempFile, err := os.CreateTemp("", "target-*.go")
	if err != nil {
		log.Printf("Failed to create temp file: %v", err)
		return "", err
	}
	tempFile.WriteString(source)
	defer func() {
		tempFile.Close()
		err := os.Remove(tempFile.Name())
		if err != nil {
			log.Printf("Failed to remove temp source file %s: %v", tempFile.Name(), err)
		}
	}()

	outName := strings.TrimSuffix(tempFile.Name(), ".go")
	goBuildCmd := exec.Command("/usr/bin/env", "go", "build", "-gcflags=all=-N -l", "-o", outName, tempFile.Name())
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

// TODO: prevent filesystem and network access in the sandbox.
// TODO: detect long-running or deadlocked programs.
// TODO: parameterize GOMAXPROCS for target program in CompileAndRun request.
func sandboxedRun(targetName string, writer io.Writer) (startedCmd *exec.Cmd, err error) {
	log.Printf("Start sandbox run of program %s", targetName)
	// The server has cpu affinity 0-(gomaxprocs-1), which is specified in the
	// driver script. And we want to give the server and the target program
	// mutually exclusive cpu affinities, so that the event reader (which runs
	// along with the server) can be scheduled to consume instrumentation events
	// as immediately as possible.
	runTargetCmd := exec.Command("taskset", "-c", fmt.Sprintf("%d-%d", gomaxprocs, 2*gomaxprocs-1), targetName)
	runTargetCmd.Stdout, runTargetCmd.Stderr = writer, writer
	runTargetCmd.WaitDelay = executionTimeLimit
	err = runTargetCmd.Start()
	if err == nil {
		startedCmd = runTargetCmd
	}
	return
}
