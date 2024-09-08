package main

import (
	"debug/elf"
	"debug/gosym"
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
