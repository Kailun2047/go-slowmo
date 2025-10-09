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

type GlobalVariableValue interface {
	uint64
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
	Target UprobeAttachTarget
	BpfFn  string
}

type UprobeAttachTarget struct {
	TargetPkg string
	TargetFn  string
}

func (in *Instrumentor) InstrumentEntry(spec UprobeAttachSpec) {
	targetSym := strings.Join([]string{spec.Target.TargetPkg, spec.Target.TargetFn}, ".")
	startOffset, err := in.interpreter.GetFunctionStartOffset(targetSym)
	if err != nil {
		log.Fatalf("Could not get start offset for target %s\n", targetSym)
	}
	_, err = in.targetExe.Uprobe(targetSym, in.bpfColl.Programs[spec.BpfFn], &link.UprobeOptions{
		Offset: startOffset,
	})
	if err != nil {
		log.Fatalf("Attach uprobe to entry for spec %+v: %v", spec, err)
	}
}

func (in *Instrumentor) InstrumentReturns(spec UprobeAttachSpec) {
	targetSym := strings.Join([]string{spec.Target.TargetPkg, spec.Target.TargetFn}, ".")
	retOffsets, err := in.interpreter.GetFunctionReturnOffset(targetSym)
	if err != nil {
		log.Fatalf("Could not get return offsets for function %s\n", targetSym)
	}
	log.Printf("Return offsets for function %s to instrument: %+v", fmt.Sprintf("%s.%s", spec.Target.TargetPkg, spec.Target.TargetFn), retOffsets)
	for _, offset := range retOffsets {
		_, err := in.targetExe.Uprobe(targetSym, in.bpfColl.Programs[spec.BpfFn], &link.UprobeOptions{
			Offset: offset,
		})
		if err != nil {
			log.Fatal("Attach go_newproc_return uprobe: ", err, ", offset: ", offset)
		}
	}
}

const delayBpfFn = "delay"

func (in *Instrumentor) Delay(target UprobeAttachTarget) {
	if len(target.TargetFn) > 0 {
		log.Printf("Delaying entry of function %s.%s", target.TargetPkg, target.TargetFn)
		in.InstrumentEntry(UprobeAttachSpec{
			Target: target,
			BpfFn:  delayBpfFn,
		})
	} else {
		pkgOffsets := in.interpreter.GetDelayableOffsetsForPackage(target.TargetPkg)
		log.Printf("Delayable offsets for package %s: %+v", target.TargetPkg, pkgOffsets)
		for fnSym, offsets := range pkgOffsets {
			for _, offset := range offsets {
				_, err := in.targetExe.Uprobe(fnSym, in.bpfColl.Programs[delayBpfFn], &link.UprobeOptions{
					Offset: offset,
				})
				if err != nil {
					log.Fatal("Attach delay uprobe: ", err)
				}
			}
		}
	}
}

func (in *Instrumentor) GetMap(name string) *ebpf.Map {
	return in.bpfColl.Maps[name]
}
