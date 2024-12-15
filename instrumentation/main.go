package main

import (
	"flag"
	"log"
)

const (
	bpfProg      = "instrumentor.o"
	localRunqLen = 256
)

var (
	targetPath = flag.String("targetpath", "", "path of the target program to be instrumented")
)

func main() {
	flag.Parse()

	byteOrder := determineByteOrder()
	log.Printf("Byte order: %v\n", byteOrder)

	interpreter := NewELFInterpreter(*targetPath)
	instrumentor := NewInstrumentor(interpreter, bpfProg)
	defer instrumentor.Close()
	instrumentor.InstrumentEntry(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "newproc",
		bpfFn:     "go_newproc",
	})
	instrumentor.InstrumentReturns(UprobeAttachSpec{
		targetPkg: "runtime",
		targetFn:  "newproc",
		bpfFn:     "go_runtime_func_return",
	})
	instrumentor.Delay(UprobeAttachSpec{
		targetPkg: "main",
		bpfFn:     "delay",
	})

	eventReader := NewEventReader(interpreter, instrumentor.GetMap("instrumentor_event"))
	defer eventReader.Close()
	eventReader.Start()
}
