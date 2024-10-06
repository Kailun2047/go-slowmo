package main

import (
	"bytes"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const symbolName = "runtime.newproc"

var byteOrder binary.ByteOrder
var symTab *gosym.Table

func main() {
	path := "../target/greet"
	byteOrder = determineByteOrder()
	symTab = getSymbolTable(path)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("RemoveMemlock: ", err)
	}

	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Fatal("OpenExecutable for tracee: ", err)
	}

	coll, err := ebpf.LoadCollection("instrumentor.o")
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			log.Fatalf("LoadCollection verifier error: %+v\n", verifierErr)
		} else {
			log.Fatal("LoadCollection: ", err)
		}
	}
	defer coll.Close()

	reader, err := ringbuf.NewReader(coll.Maps["newproc_fn_pc_cnt"])
	if err != nil {
		log.Fatal("Create ring buffer reader: ", err)
	}
	defer reader.Close()

	_, err = ex.Uprobe(symbolName, coll.Programs["go_newproc"], &link.UprobeOptions{})
	if err != nil {
		log.Fatal("Attach go_newproc uprobe: ", err)
	}

	pkgOffsets := getInstrumentableOffsetsForPackage(symTab, "main")
	log.Printf("Instrumentable offsets: %+v", pkgOffsets)
	for fnSym, offsets := range pkgOffsets {
		for _, offset := range offsets {
			_, err = ex.Uprobe(fnSym, coll.Programs["delay"], &link.UprobeOptions{
				Offset: offset,
			})
			if err != nil {
				log.Fatal("Attach delay uprobe: ", err)
			}
		}
	}

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-stop:
			log.Print("Received signal, exiting...")
			return
		case <-ticker.C:
			var newprocPC uint64
			reader.SetDeadline(time.Now().Add(1 * time.Second))
			record, err := reader.Read()
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					log.Fatal("Read ring buffer: ", err)
				}
				break
			}
			err = binary.Read(bytes.NewBuffer(record.RawSample), byteOrder, &newprocPC)
			if err != nil {
				log.Fatal("Decode ring buffer record: ", err)
			}
			file, line, _ := symTab.PCToLine(newprocPC)
			log.Printf("newproc invoked (pc: %x, file: %s, line: %d)\n", newprocPC, file, line)
		}
	}
}
