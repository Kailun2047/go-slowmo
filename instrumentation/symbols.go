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
	text     *elf.Section
}

func NewELFInterpreter(prog string) *ELFInterpreter {
	exe, err := elf.Open(prog)
	if err != nil {
		log.Fatal("Open ELF file: ", err)
	}
	return &ELFInterpreter{
		goSymTab: getGoSymbolTable(exe),
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
		fmt.Println(fn.Type, fn.GoType)

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

		for ln := startLn; ln <= endLn; ln++ {
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

func (ei *ELFInterpreter) GetFunctionReturnOffset(fnName string) []uint64 {
	var (
		fnPtr      *gosym.Func
		buf        []byte
		retOffsets []uint64 = []uint64{}
	)
	for _, fn := range ei.goSymTab.Funcs {
		if fn.Name == fnName {
			fnPtr = &fn
			break
		}
	}
	if fnPtr == nil {
		log.Printf("Symbol table entry for function %s not found\n", fnName)
		return retOffsets
	}
	buf = make([]byte, fnPtr.End-fnPtr.Entry)
	_, err := ei.text.ReadAt(buf, int64(fnPtr.Entry))
	if err != nil {
		log.Fatalf("Read symbol %s in .text section: %v\n", fnName, err)
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
	return retOffsets
}
