package main

import (
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"log"

	"golang.org/x/arch/x86/x86asm"
)

type ELFInterpreter struct {
	goSymTab *gosym.Table
	symbols  []elf.Symbol
	text     *elf.Section
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
	return &ELFInterpreter{
		goSymTab: getGoSymbolTable(exe),
		symbols:  symbols,
		text:     getSection(exe, ".text"),
	}
}

func getGoSymbolTable(exe *elf.File) *gosym.Table {
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
	return tab
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
			} else {
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
