package main

import (
	"errors"
	"log"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	instrumentor         *Instrumentor
	initInstrumentorOnce sync.Once
)

type Instrumentor struct {
	interpreter *ELFInterpreter
	targetExe   *link.Executable
	bpfColl     *ebpf.Collection
}

func NewInstrumentor(interpreter *ELFInterpreter, bpfProg string) *Instrumentor {
	initInstrumentor(interpreter, bpfProg)
	return instrumentor
}

func initInstrumentor(interpreter *ELFInterpreter, bpfProg string) {
	if instrumentor != nil {
		return
	}
	initInstrumentorOnce.Do(func() {
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatal("RemoveMemlock: ", err)
		}
		exe, err := link.OpenExecutable(*targetPath)
		if err != nil {
			log.Fatal("OpenExecutable for tracee: ", err)
		}
		coll, err := ebpf.LoadCollection(bpfProg)
		if err != nil {
			var verifierErr *ebpf.VerifierError
			if errors.As(err, &verifierErr) {
				log.Fatalf("LoadCollection verifier error: %+v\n", verifierErr)
			} else {
				log.Fatal("LoadCollection: ", err)
			}
		}
		instrumentor = &Instrumentor{
			interpreter: interpreter,
			targetExe:   exe,
			bpfColl:     coll,
		}
	})
}

func (in *Instrumentor) Close() {
	in.bpfColl.Close()
}

type UprobeAttachSpec struct {
	targetPkg string
	targetFn  string
	bpfFn     string
}

func (in *Instrumentor) InstrumentEntry(spec UprobeAttachSpec) {
	targetSym := strings.Join([]string{spec.targetPkg, spec.targetFn}, ".")
	startOffset, err := in.interpreter.GetFunctionStartOffset(targetSym)
	if err != nil {
		log.Fatalf("Could not get start offset for target %s\n", targetSym)
	}
	_, err = in.targetExe.Uprobe(targetSym, in.bpfColl.Programs[spec.bpfFn], &link.UprobeOptions{
		Offset: startOffset,
	})
	if err != nil {
		log.Fatal("Attach uprobe to entry: ", err)
	}
}

func (in *Instrumentor) InstrumentReturns(spec UprobeAttachSpec) {
	targetSym := strings.Join([]string{spec.targetPkg, spec.targetFn}, ".")
	retOffsets, err := in.interpreter.GetFunctionReturnOffset(targetSym)
	if err != nil {
		log.Fatalf("Could not get return offsets for function %s\n", targetSym)
	}
	log.Printf("Return offsets to instrument: %+v", retOffsets)
	for _, offset := range retOffsets {
		_, err := in.targetExe.Uprobe(targetSym, in.bpfColl.Programs[spec.bpfFn], &link.UprobeOptions{
			Offset: offset,
		})
		if err != nil {
			log.Fatal("Attach go_newproc_return uprobe: ", err, ", offset: ", offset)
		}
	}
}

func (in *Instrumentor) Delay(spec UprobeAttachSpec) {
	if len(spec.targetFn) > 0 {
		log.Fatal("Delay of specific function in target package is not supported")
	}
	pkgOffsets := in.interpreter.GetDelayableOffsetsForPackage(spec.targetPkg)
	log.Printf("Delayable offsets for package %s: %+v", spec.targetPkg, pkgOffsets)
	for fnSym, offsets := range pkgOffsets {
		for _, offset := range offsets {
			_, err := in.targetExe.Uprobe(fnSym, in.bpfColl.Programs[spec.bpfFn], &link.UprobeOptions{
				Offset: offset,
			})
			if err != nil {
				log.Fatal("Attach delay uprobe: ", err)
			}
		}
	}
}

func (in *Instrumentor) GetMap(name string) *ebpf.Map {
	return in.bpfColl.Maps[name]
}
