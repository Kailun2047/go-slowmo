package main

import (
	"debug/elf"
	"debug/gosym"
	"errors"
	"log"
)

func getSymbolTable(prog string) *gosym.Table {
	exe, err := elf.Open(prog)
	if err != nil {
		log.Fatal("Open program object file: ", err)
	}
	defer exe.Close()

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

type symbolOffsets = map[string][]uint64

func getInstrumentableOffsetsForPackage(symTab *gosym.Table, pkgName string) symbolOffsets {
	var symOffsets symbolOffsets = make(map[string][]uint64)

	for _, fn := range symTab.Funcs {
		if fn.PackageName() != pkgName {
			continue
		}

		file, startLn, _ := symTab.PCToLine(fn.Entry)
		endLn := startLn
		// Look for the max line number of target function. Termination
		// condition is pc < fn.End because fn.End holds the entry PC value of
		// the next function instead of the last PC value of our target
		// function.
		for pc := fn.Entry; pc < fn.End; pc++ {
			curFile, curEndLn, curFn := symTab.PCToLine(pc)
			if curFn != nil && curFn.Name == fn.Name && curFile == file {
				endLn = max(endLn, curEndLn)
			}
		}

		for ln := startLn; ln <= endLn; ln++ {
			pc, curFn, err := symTab.LineToPC(file, ln)
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
