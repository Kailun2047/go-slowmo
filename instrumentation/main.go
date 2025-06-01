package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	bpfProg = "instrumentor.o"
)

var (
	targetPath = flag.String("targetpath", "", "path of the target program to be instrumented")
)

func main() {
	flag.Parse()

	interpreter := NewELFInterpreter(*targetPath)

	runtimeSchedAddr := interpreter.GetGlobalVariableAddr("runtime.sched")
	semTableAddr := interpreter.GetGlobalVariableAddr("runtime.semtable")
	pctab := interpreter.GetPCTab()
	instrumentor := NewInstrumentor(
		interpreter, bpfProg,
		WithGlobalVariable(GlobalVariable[uint64]{
			NameInBPFProg: "runtime_sched_addr",
			Value:         runtimeSchedAddr,
		}),
		WithGlobalVariable(GlobalVariable[instrumentorGoPctab]{
			NameInBPFProg: "pctab",
			Value:         instrumentorGoPctab{Size: uint64(len(pctab)), DataAddr: *(*uint64)(unsafe.Pointer(&pctab[0]))},
		}),
		WithGlobalVariable(GlobalVariable[uint64]{
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

	instrumentor.InstrumentEntry(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "newproc",
		bpfFn:     "go_newproc",
	})
	instrumentor.InstrumentReturns(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "newproc",
		bpfFn:     "go_runtime_func_ret_runq_status",
	})
	instrumentor.InstrumentReturns(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "runqget",
		bpfFn:     "go_runtime_func_ret_runq_status",
	})
	instrumentor.InstrumentEntry(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "runqsteal",
		bpfFn:     "go_runqsteal",
	})
	instrumentor.InstrumentReturns(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "runqsteal",
		bpfFn:     "go_runqsteal_ret_runq_status",
	})
	instrumentor.InstrumentEntry(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "execute",
		bpfFn:     "go_execute",
	})
	instrumentor.InstrumentReturns(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "globrunqget",
		bpfFn:     "globrunq_status",
	})
	instrumentor.InstrumentReturns(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "globrunqput",
		bpfFn:     "globrunq_status",
	})
	instrumentor.InstrumentEntry((UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "gopark",
		bpfFn:     "gopark",
	}))
	instrumentor.Delay(UprobeAttachSpec{
		targetPkg: "main",
		bpfFn:     "delay",
	})

	eventReader := NewEventReader(interpreter, instrumentor.GetMap("instrumentor_event"))
	defer eventReader.Close()
	eventReader.Start()
}
