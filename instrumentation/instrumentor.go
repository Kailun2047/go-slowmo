package instrumentation

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Instrumentor struct {
	interpreter *ELFInterpreter
	targetExe   *link.Executable
	bpfColl     *ebpf.Collection
}

type InstrumentorOption func(*ELFInterpreter, *ebpf.CollectionSpec)

type InstrumentorGoPctab = instrumentorGoPctab

type GlobalVariableValue interface {
	uint64 | InstrumentorGoPctab
}

type GlobalVariable[T GlobalVariableValue] struct {
	NameInBPFProg string
	Value         T
}

func WithGlobalVariable[T GlobalVariableValue](variable GlobalVariable[T]) InstrumentorOption {
	return func(interpreter *ELFInterpreter, spec *ebpf.CollectionSpec) {
		varSpec := spec.Variables[variable.NameInBPFProg]
		if varSpec == nil {
			log.Fatalf("Global variable %s not found in loaded BPF specification", variable.NameInBPFProg)
		}
		varSpec.Set(variable.Value)
	}
}

func NewInstrumentor(interpreter *ELFInterpreter, bpfProg, targetPath string, opts ...InstrumentorOption) *Instrumentor {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("RemoveMemlock: ", err)
	}
	exe, err := link.OpenExecutable(targetPath)
	if err != nil {
		log.Fatal("OpenExecutable for tracee: ", err)
	}
	spec, err := ebpf.LoadCollectionSpec(bpfProg)
	if err != nil {
		log.Fatal("LoadCollectionSpec: ", err)
	}
	for _, opt := range opts {
		opt(interpreter, spec)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			log.Fatalf("LoadCollection verifier error: %+v\n", verifierErr)
		} else {
			log.Fatal("LoadCollection: ", err)
		}
	}
	return &Instrumentor{
		interpreter: interpreter,
		targetExe:   exe,
		bpfColl:     coll,
	}
}

func (in *Instrumentor) Close() {
	in.bpfColl.Close()
}

type UprobeAttachSpec struct {
	TargetPkg string
	TargetFn  string
	BpfFn     string
}

func (in *Instrumentor) InstrumentEntry(spec UprobeAttachSpec) {
	targetSym := strings.Join([]string{spec.TargetPkg, spec.TargetFn}, ".")
	startOffset, err := in.interpreter.GetFunctionStartOffset(targetSym)
	if err != nil {
		log.Fatalf("Could not get start offset for target %s\n", targetSym)
	}
	_, err = in.targetExe.Uprobe(targetSym, in.bpfColl.Programs[spec.BpfFn], &link.UprobeOptions{
		Offset: startOffset,
	})
	if err != nil {
		log.Fatal("Attach uprobe to entry: ", err)
	}
}

func (in *Instrumentor) InstrumentReturns(spec UprobeAttachSpec) {
	targetSym := strings.Join([]string{spec.TargetPkg, spec.TargetFn}, ".")
	retOffsets, err := in.interpreter.GetFunctionReturnOffset(targetSym)
	if err != nil {
		log.Fatalf("Could not get return offsets for function %s\n", targetSym)
	}
	log.Printf("Return offsets for function %s to instrument: %+v", fmt.Sprintf("%s.%s", spec.TargetPkg, spec.TargetFn), retOffsets)
	for _, offset := range retOffsets {
		_, err := in.targetExe.Uprobe(targetSym, in.bpfColl.Programs[spec.BpfFn], &link.UprobeOptions{
			Offset: offset,
		})
		if err != nil {
			log.Fatal("Attach go_newproc_return uprobe: ", err, ", offset: ", offset)
		}
	}
}

func (in *Instrumentor) Delay(spec UprobeAttachSpec) {
	if len(spec.TargetFn) > 0 {
		log.Fatal("Delay of specific function in target package is not supported")
	}
	pkgOffsets := in.interpreter.GetDelayableOffsetsForPackage(spec.TargetPkg)
	log.Printf("Delayable offsets for package %s: %+v", spec.TargetPkg, pkgOffsets)
	for fnSym, offsets := range pkgOffsets {
		for _, offset := range offsets {
			_, err := in.targetExe.Uprobe(fnSym, in.bpfColl.Programs[spec.BpfFn], &link.UprobeOptions{
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
