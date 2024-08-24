package main

import (
	"debug/elf"
	"log"
	"os"
	"os/signal"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const SymbolName = "main.Greet"

type GreetEvent struct {
	Msg [6]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	path := "../greet/greet"
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

	greetEvents, err := ringbuf.NewReader(coll.Maps["greet_params"])
	if err != nil {
		log.Fatal(err)
	}

	stop := make(chan os.Signal, 5)
	done := make(chan struct{})
	signal.Notify(stop, os.Interrupt)
	go func() {
		defer close(done)
		countMap := map[string]uint64{}
		for {
			select {
			case <-stop:
				log.Print("Received signal, exiting...")
				return
			default:
				event, err := greetEvents.Read()
				if err != nil {
					log.Fatal(err)
				}
				greetEvent := (*GreetEvent)(unsafe.Pointer(&event.RawSample[0]))
				countMap[string(greetEvent.Msg[:])]++
				log.Printf("COUNT: %v", countMap)
			}
		}
	}()

	_, err = ex.Uprobe(SymbolName, coll.Programs["go_test_greet"], &link.UprobeOptions{})
	if err != nil {
		log.Fatal(err)
	}
	<-done
}
