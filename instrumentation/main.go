package main

import (
	"flag"
	"log"
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

	addr := interpreter.GetGlobalVariableAddr("runtime.sched")
	pctab := interpreter.GetPCTab()
	instrumentor := NewInstrumentor(
		interpreter, bpfProg,
		WithGlobalVariable(GlobalVariable[uint64]{
			NameInBPFProg: "runtime_sched_addr",
			Value:         addr,
		}),
		WithGlobalVariable(GlobalVariable[instrumentorGoPctab]{
			NameInBPFProg: "pctab",
			Value:         instrumentorGoPctab{Size: uint64(len(pctab)), DataAddr: *(*uint64)(unsafe.Pointer(&pctab[0]))},
		}),
	)

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
	instrumentor.Delay(UprobeAttachSpec{
		targetPkg: "main",
		bpfFn:     "delay",
	})

	eventReader := NewEventReader(interpreter, instrumentor.GetMap("instrumentor_event"))
	defer eventReader.Close()
	eventReader.Start()
}
