package main

import (
	"flag"
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
	instrumentor := NewInstrumentor(interpreter, bpfProg, WithGlobalVariableAddrs([]GlobalVariable{
		{NameInBPFProg: "runtime_sched_addr", NameInTargetProg: "runtime.sched"},
	}))
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
