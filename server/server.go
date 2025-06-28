package server

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/kailun2047/slowmo/instrumentation"
)

func StartInstrumentation(bpfProg, targetPath string) {
	flag.Parse()

	interpreter := instrumentation.NewELFInterpreter(targetPath)

	runtimeSchedAddr := interpreter.GetGlobalVariableAddr("runtime.sched")
	semTableAddr := interpreter.GetGlobalVariableAddr("runtime.semtable")
	pctab := interpreter.GetPCTab()
	instrumentor := instrumentation.NewInstrumentor(
		interpreter,
		bpfProg,
		targetPath,
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[uint64]{
			NameInBPFProg: "runtime_sched_addr",
			Value:         runtimeSchedAddr,
		}),
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[instrumentation.InstrumentorGoPctab]{
			NameInBPFProg: "pctab",
			Value:         instrumentation.InstrumentorGoPctab{Size: uint64(len(pctab)), DataAddr: *(*uint64)(unsafe.Pointer(&pctab[0]))},
		}),
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[uint64]{
			NameInBPFProg: "semtab_addr",
			Value:         semTableAddr,
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

	// Initialize the map-in-map with GOMAXPROCS stacks for the ebpf program to
	// inspect semtable without potential race condition.
	//
	// Assumptions made here:
	//
	// 1. GOMAXPROCS defaults to num of logical CPUs
	//
	// 2. the instrumentor and the instrumented program perceive the same value
	// for GOMAXPROCS;
	//
	// 3. the IDs of processors ("P") are orderded, 0-based numbers.
	//
	// Adjustment is needed if any of the above assumptions doesn't hold true.
	sudogStacks := instrumentor.GetMap("sudog_stacks")
	for i := range runtime.NumCPU() {
		sudogStackName := fmt.Sprintf("sudog_stack_%d", i)
		sudogStack, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       sudogStackName,
			Type:       ebpf.Stack,
			ValueSize:  8, // a sudog stack will hold pointers to sudogs
			MaxEntries: 10,
		})
		if err != nil {
			log.Fatalf("Error creating sudog stack map %s: %v", sudogStackName, err)
		}
		err = sudogStacks.Update(uint32(i), sudogStack, ebpf.UpdateAny)
		if err != nil {
			log.Fatalf("Error inserting inner sudog stack map %s into outer map: %v", sudogStackName, err)
		}
	}

	defer instrumentor.Close()

	instrumentor.InstrumentEntry(instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "newproc",
		BpfFn:     "go_newproc",
	})
	instrumentor.InstrumentReturns(instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "newproc",
		BpfFn:     "go_runtime_func_ret_runq_status",
	})
	instrumentor.InstrumentReturns(instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "runqget",
		BpfFn:     "go_runtime_func_ret_runq_status",
	})
	instrumentor.InstrumentEntry(instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "runqsteal",
		BpfFn:     "go_runqsteal",
	})
	instrumentor.InstrumentReturns(instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "runqsteal",
		BpfFn:     "go_runqsteal_ret_runq_status",
	})
	instrumentor.InstrumentEntry(instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "execute",
		BpfFn:     "go_execute",
	})
	instrumentor.InstrumentReturns(instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "globrunqget",
		BpfFn:     "globrunq_status",
	})
	instrumentor.InstrumentReturns(instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "globrunqput",
		BpfFn:     "globrunq_status",
	})
	instrumentor.InstrumentEntry((instrumentation.UprobeAttachSpec{
		TargetPkg: "runtime",
		TargetFn:  "gopark",
		BpfFn:     "gopark",
	}))
	// Temporarily disable the delay probe to avoid triggering preemption.
	// TODO: handle preemption properly or disable preemption.
	// instrumentor.Delay(instrumentation.UprobeAttachSpec{
	// 	TargetPkg: "main",
	// 	TpfFn:     "delay",
	// }B

	eventReader := instrumentation.NewEventReader(interpreter, instrumentor.GetMap("instrumentor_event"))
	defer eventReader.Close()
	eventReader.Start()
}
