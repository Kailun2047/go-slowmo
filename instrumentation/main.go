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
		err := functabMap.Update(i, funcInfo, ebpf.UpdateNoExist)
		if err != nil {
			log.Fatalf("error writing function info %v into go_functab map: %v", funcInfo, err)
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
