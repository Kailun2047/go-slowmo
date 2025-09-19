package instrumentation

import (
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"reflect"
	"slices"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
)

const (
	symTabFieldNameGo12Line = "go12line"
	lnTabFieldNameFuncTabN  = "nfunctab"
	lnTabFieldNameTextStart = "textStart"

	// functab and funcdata are 2 parts of a single byte chunk, where functab
	// acts as index and funcdata is the actual data (i.e. _func structures).
	lnTabFieldNameFuncTab  = "functab"
	lnTabFieldNameFuncData = "funcdata"

	funcInfoFieldOffsetPCSP = 16
	funcInfoFieldOffsetFlag = 41
)

type ELFInterpreter struct {
	goSymTab *gosym.Table // gosym.Table.Syms is nil for go later than 1.3 so we need to consult symbols instead of goSymTab when we need to inspect symbols
	goLnTab  *gosym.LineTable
	symbols  []elf.Symbol
	text     *elf.Section
	// The byte order info is actually included as an unexported field in
	// LineTable. Retrieve and store it in a dedicated field for convenience.
	byteOrder binary.ByteOrder
}

func NewELFInterpreter(prog string) *ELFInterpreter {
	exe, err := elf.Open(prog)
	if err != nil {
		log.Fatal("Open ELF file: ", err)
	}
	symbols, err := exe.Symbols()
	if err != nil {
		log.Fatalf("Load ELF symbols for file %s: %v\n", prog, err)
	}
	slices.SortFunc(symbols, func(a, b elf.Symbol) int {
		if a.Value < b.Value {
			return -1
		} else {
			return 1
		}
	})
	lnTab, symTab := getGoSymbolTable(exe)
	return &ELFInterpreter{
		goSymTab:  symTab,
		goLnTab:   lnTab,
		symbols:   symbols,
		text:      getSection(exe, ".text"),
		byteOrder: determineByteOrder(),
	}
}

func getGoSymbolTable(exe *elf.File) (*gosym.LineTable, *gosym.Table) {
	textSeg := getSection(exe, ".text")
	lnTabSeg := getSection(exe, ".gopclntab")
	lnTabData, err := lnTabSeg.Data()
	if err != nil {
		log.Fatal("Read line table data: ", err)
	}

	lnTab := gosym.NewLineTable(lnTabData, textSeg.Addr)
	symTabSeg := getSection(exe, ".gosymtab")
	symTabData, err := symTabSeg.Data()
	if err != nil {
		log.Fatal("Read symbol table data: ", err)
	}
	tab, err := gosym.NewTable(symTabData, lnTab)
	if err != nil {
		log.Fatal("Create symbol table: ", err)
	}
	return lnTab, tab
}

func getSection(exe *elf.File, name string) *elf.Section {
	sec := exe.Section(name)
	if sec == nil {
		log.Fatalf("Segment %s not found\n", name)
	}
	return sec
}

func (ei *ELFInterpreter) PCToLine(pc uint64) (file string, line int, fn *gosym.Func) {
	return ei.goSymTab.PCToLine(pc)
}

type SymbolOffsets = map[string][]uint64

func (ei *ELFInterpreter) GetDelayableOffsetsForPackage(pkgName string) SymbolOffsets {
	var symOffsets SymbolOffsets = make(map[string][]uint64)

	for _, fn := range ei.goSymTab.Funcs {
		if fn.PackageName() != pkgName {
			continue
		}
		file, startLn, _ := ei.goSymTab.PCToLine(fn.Entry)
		endLn := startLn

		// Look for the max line number of target function. Termination
		// condition is pc < fn.End because fn.End holds the entry PC value of
		// the next function instead of the last PC value of our target
		// function.
		for pc := fn.Entry; pc < fn.End; pc++ {
			curFile, curEndLn, curFn := ei.goSymTab.PCToLine(pc)
			if curFn != nil && curFn.Name == fn.Name && curFile == file {
				endLn = max(endLn, curEndLn)
			}
		}

		// For starting line, skip the prologue.
		startOffset, err := ei.GetFunctionStartOffset(fn.Name)
		if err != nil {
			log.Fatalf("Fails to find start offset for function %s\n", fn.Name)
		}
		symOffsets[fn.Name] = append(symOffsets[fn.Name], startOffset)

		for ln := startLn + 1; ln <= endLn; ln++ {
			pc, curFn, err := ei.goSymTab.LineToPC(file, ln)
			var unknownLnErr *gosym.UnknownLineError
			if err != nil {
				if !errors.As(err, &unknownLnErr) {
					log.Fatalf("getInstrumentablePCsForFunc: error finding PC for line %d in file %s: %v", ln, file, err)
				}
			} else if curFn != nil && curFn.Name == fn.Name {
				symOffsets[curFn.Name] = append(symOffsets[curFn.Name], pc-curFn.Entry)
			}
		}
	}
	return symOffsets
}

func (ei *ELFInterpreter) getInstsFromTextSection(fnName string) ([]byte, error) {
	var (
		fnSym elf.Symbol
		buf   []byte
	)

	for _, symbol := range ei.symbols {
		if symbol.Name == fnName {
			fnSym = symbol
			break
		}
	}
	if len(fnSym.Name) == 0 {
		return buf, fmt.Errorf("symbol table entry for function %s not found\n", fnName)
	}
	buf = make([]byte, fnSym.Size)
	_, err := ei.text.ReadAt(buf, int64(fnSym.Value-ei.text.Addr))
	return buf, err
}

func (ei *ELFInterpreter) GetFunctionReturnOffset(fnName string) ([]uint64, error) {
	retOffsets := []uint64{}
	buf, err := ei.getInstsFromTextSection(fnName)
	if err != nil {
		return retOffsets, err
	}
	for offset := 0; offset < len(buf); {
		inst, err := x86asm.Decode(buf[offset:], 64)
		if err != nil {
			log.Fatalf("Decode instruction for symbol %s at offset %d: %v\n", fnName, offset, err)
		}
		if inst.Op == x86asm.RET {
			retOffsets = append(retOffsets, uint64(offset))
		}
		offset += inst.Len
	}
	return retOffsets, nil
}

var prologueOpSequence = []x86asm.Op{x86asm.CMP, x86asm.JBE}

// Get the PC of the first instruction after the stack-splitting prologue in a
// go function.
func (ei *ELFInterpreter) GetFunctionStartOffset(fnName string) (uint64, error) {
	buf, err := ei.getInstsFromTextSection(fnName)
	if err != nil {
		return 0, err
	}
	offset, prologueIdxToMatch, nextSearchStart := 0, 0, 0
	for offset < len(buf) {
		inst, err := x86asm.Decode(buf[offset:], 64)
		if err != nil {
			log.Fatalf("Decode instruction for symbol %s at offset %d: %v\n", fnName, offset, err)
		}
		if prologueIdxToMatch == 0 {
			nextSearchStart = offset + inst.Len
		}
		if inst.Op == prologueOpSequence[prologueIdxToMatch] {
			prologueIdxToMatch++
			offset += inst.Len
			if prologueIdxToMatch == len(prologueOpSequence) {
				break
			}
		} else {
			offset = nextSearchStart
		}
	}
	if prologueIdxToMatch < len(prologueOpSequence) {
		log.Fatalf("Prologue sequence not found in function %s\n", fnName)
	}
	return uint64(offset), nil
}

func (ei *ELFInterpreter) GetGlobalVariableAddr(varName string) uint64 {
	var targetSym elf.Symbol
	for _, sym := range ei.symbols {
		if sym.Name == varName {
			targetSym = sym
			break
		}
	}
	if targetSym.Value == 0 {
		log.Fatalf("Global variable %s not found in target program", varName)
	}
	return targetSym.Value
}

func (ei *ELFInterpreter) ParseFuncTab() []instrumentorGoFuncInfo {
	var (
		res              []instrumentorGoFuncInfo
		nfunctab         uint32
		funcTab          []byte
		funcData         []byte
		funcTabFieldSize = 4 // Size in bytes of a single functab field; 4 for go version >= 1.18
		textStart        uint64
	)
	lnTabV := reflect.ValueOf(ei.goLnTab).Elem()
	nfunctab = uint32(lnTabV.FieldByName(lnTabFieldNameFuncTabN).Uint())
	funcTabV := lnTabV.FieldByName(lnTabFieldNameFuncTab)
	funcTab = *(*[]byte)(unsafe.Pointer(funcTabV.UnsafeAddr()))
	funcDataV := lnTabV.FieldByName(lnTabFieldNameFuncData)
	funcData = *(*[]byte)(unsafe.Pointer(funcDataV.UnsafeAddr()))
	textStart = lnTabV.FieldByName(lnTabFieldNameTextStart).Uint()

	for i := range nfunctab {
		funcOff := uint64(ei.byteOrder.Uint32(funcTab[(2*i+1)*uint32(funcTabFieldSize):]))
		funcInfoData := funcData[funcOff:] // The byte chunk of _func struct

		// Collect data from per-function information
		// (https://github.com/golang/go/blob/go1.22.5/src/runtime/runtime2.go#L936).
		entryOff := uint64(ei.byteOrder.Uint32(funcInfoData))
		pcsp := ei.byteOrder.Uint32(funcInfoData[funcInfoFieldOffsetPCSP:])
		flag := funcInfoData[funcInfoFieldOffsetFlag]
		res = append(res, instrumentorGoFuncInfo{
			EntryPc: textStart + entryOff,
			Pcsp:    pcsp,
			Flag:    flag,
		})
	}

	return res
}

// SymByDataElemAddr is used to find the symbol to which a data element belongs
// (e.g. to find out the variable for a given data element address in a sudog).
func (ei *ELFInterpreter) SymByDataElemAddr(dataElemAddr uint64) string {
	target := elf.Symbol{
		Value: dataElemAddr,
	}
	idx, found := slices.BinarySearchFunc(ei.symbols, target, func(sym, target elf.Symbol) int {
		if sym.Value < target.Value {
			return -1
		} else if sym.Value > target.Value {
			return 1
		} else {
			return 0
		}
	})
	if idx == len(ei.symbols) {
		// The last entry in symbol table holds special symbol which doesn't
		// match actual symbol in go program. At this point we know the data
		// element can't be found in the symbol table, and is something on
		// stack.
		return "data element on stack"
	} else if found {
		return ei.symbols[idx].Name
	} else {
		return ei.symbols[idx-1].Name
	}
}
