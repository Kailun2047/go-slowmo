package main

import (
	"bytes"
	"debug/elf"
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

const SymbolName = "runtime.newproc"

var byteOrder binary.ByteOrder
var symTab *gosym.Table

func main() {
	path := "../target/greet"
	byteOrder = determineByteOrder()
	symTab = getSymbolTable(path)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// open in elf format in order to get the symbols
	ef, err := elf.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer ef.Close()

	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.LoadCollection("tracker.o")
	if err != nil {
		log.Fatal(err)
	}

	reader, err := ringbuf.NewReader(coll.Maps["newproc_fn_pc_cnt"])
	if err != nil {
		log.Fatal("Create ring buffer reader: ", err)
	}
	defer reader.Close()

	_, err = ex.Uprobe(SymbolName, coll.Programs["go_newproc"], &link.UprobeOptions{})
	if err != nil {
		log.Fatal("Attach uprobe: ", err)
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
