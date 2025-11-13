package instrumentation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kailun2047/slowmo/logging"
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
			logging.Logger().Fatalf("Global variable %s not found in loaded BPF specification", variable.NameInBPFProg)
		}
		varSpec.Set(variable.Value)
	}
}

func NewInstrumentor(interpreter *ELFInterpreter, bpfProg, targetPath string, opts ...InstrumentorOption) *Instrumentor {
	if err := rlimit.RemoveMemlock(); err != nil {
		logging.Logger().Fatal("RemoveMemlock: ", err)
	}
	exe, err := link.OpenExecutable(targetPath)
	if err != nil {
		logging.Logger().Fatal("OpenExecutable for tracee: ", err)
	}
	spec, err := ebpf.LoadCollectionSpec(bpfProg)
	if err != nil {
		logging.Logger().Fatal("LoadCollectionSpec: ", err)
	}
	for _, opt := range opts {
		opt(interpreter, spec)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			logging.Logger().Fatalf("LoadCollection verifier error: %+v\n", verifierErr)
		} else {
			logging.Logger().Fatal("LoadCollection: ", err)
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

type FunctionAttachOffset int

const (
	AttachOffsetEntry FunctionAttachOffset = iota
	AttachOffsetReturns
)

type FunctionSpec struct {
	TargetPkg    string
	TargetFn     string
	AttachOffset FunctionAttachOffset
	BpfFns       []string
}

type PackageSpec struct {
	TargetPkg string
	BpfFns    []string
}

func (in *Instrumentor) InstrumentFunction(spec FunctionSpec) {
	if spec.AttachOffset == AttachOffsetEntry {
		in.instrumentFunctionEntry(spec.TargetPkg, spec.TargetFn, spec.BpfFns)
	} else {
		in.instrumentFunctionReturns(spec.TargetPkg, spec.TargetFn, spec.BpfFns)
	}
}

func (in *Instrumentor) instrumentFunctionEntry(targetPkg, targetFn string, bpfFns []string) {
	targetSym := strings.Join([]string{targetPkg, targetFn}, ".")
	startOffset, err := in.interpreter.GetFunctionStartOffset(targetSym)
	if err != nil {
		logging.Logger().Fatalf("Could not get start offset for target %s\n", targetSym)
	}
	for _, bpfFn := range bpfFns {
		_, err = in.targetExe.Uprobe(targetSym, in.bpfColl.Programs[bpfFn], &link.UprobeOptions{
			Offset: startOffset,
		})
		if err != nil {
			logging.Logger().Fatalf("Attach uprobe %s to entry for %s:%s: %v", bpfFn, targetPkg, targetFn, err)
		}
	}
}

func (in *Instrumentor) instrumentFunctionReturns(targetPkg, targetFn string, bpfFns []string) {
	targetSym := strings.Join([]string{targetPkg, targetFn}, ".")
	retOffsets, err := in.interpreter.GetFunctionReturnOffset(targetSym)
	if err != nil {
		logging.Logger().Fatalf("Could not get return offsets for function %s\n", targetSym)
	}
	logging.Logger().Debugf("Return offsets for function %s to instrument: %+v", fmt.Sprintf("%s.%s", targetPkg, targetFn), retOffsets)
	for _, offset := range retOffsets {
		for _, bpfFn := range bpfFns {
			_, err := in.targetExe.Uprobe(targetSym, in.bpfColl.Programs[bpfFn], &link.UprobeOptions{
				Offset: offset,
			})
			if err != nil {
				logging.Logger().Fatal("Attach go_newproc_return uprobe: ", err, ", offset: ", offset)
			}
		}
	}
}

func (in *Instrumentor) InstrumentPackage(spec PackageSpec) {
	pkgOffsets := in.interpreter.GetInstrumentableOffsetsForPackage(spec.TargetPkg)
	logging.Logger().Debugf("Delayable offsets for package %s: %+v", spec.TargetPkg, pkgOffsets)
	for fnSym, offsets := range pkgOffsets {
		for _, offset := range offsets {
			for _, bpfFn := range spec.BpfFns {
				_, err := in.targetExe.Uprobe(fnSym, in.bpfColl.Programs[bpfFn], &link.UprobeOptions{
					Offset: offset,
				})
				if err != nil {
					logging.Logger().Fatal("Attach delay uprobe: ", err)
				}
			}
		}
	}
}

func (in *Instrumentor) GetMap(name string) *ebpf.Map {
	return in.bpfColl.Maps[name]
}
