package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const symbolNameNewproc = "runtime.newproc"

var (
	byteOrder   binary.ByteOrder
	interpreter *ELFInterpreter

	targetPath = flag.String("targetpath", "", "path of the target program to be instrumented")
)

// Go equivalents of instrumentor events.
type eventType uint64

const (
	EVENT_TYPE_NEWPROC eventType = iota
	EVENT_TYPE_DELAY
)

type newprocEvent struct {
	EType       eventType
	PC          uint64
	CreatorGoid uint64
}
type delayEvent struct {
	EType eventType
	PC    uint64
}

func main() {
	flag.Parse()

	byteOrder = determineByteOrder()
	interpreter = NewELFInterpreter(*targetPath)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("RemoveMemlock: ", err)
	}

	ex, err := link.OpenExecutable(*targetPath)
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

	_, err = ex.Uprobe(symbolNameNewproc, coll.Programs["go_newproc"], &link.UprobeOptions{})
	if err != nil {
		log.Fatal("Attach go_newproc uprobe: ", err)
	}

	pkgOffsets := interpreter.GetDelayableOffsetsForPackage("main")
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

	eventReader, err := ringbuf.NewReader(coll.Maps["instrumentor_event"])
	if err != nil {
		log.Fatal("Create ring buffer reader: ", err)
	}
	defer eventReader.Close()
	eventCh := createEventChan(eventReader)

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		case record := <-eventCh:
			var etype eventType
			reader := bytes.NewReader(record.RawSample)
			err := binary.Read(reader, byteOrder, &etype)
			if err != nil {
				log.Fatal("Decode event type: ", err)
			}
			err = readEvent(reader, etype)
			if err != nil {
				log.Fatalf("Decode event type %v: %v\n", etype, err)
			}
		}
	}
}

func createEventChan(eventReader *ringbuf.Reader) chan ringbuf.Record {
	eventCh := make(chan ringbuf.Record)
	go func() {
		for {
			eventReader.SetDeadline(time.Now().Add(1 * time.Second))
			record, err := eventReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Event reader closed")
					return
				}
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					log.Fatal("Read ring buffer: ", err)
				}
			} else {
				eventCh <- record
			}
		}
	}()

	return eventCh
}

func readEvent(readSeeker io.ReadSeeker, etype eventType) error {
	var err error

	_, err = readSeeker.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	switch etype {
	case EVENT_TYPE_NEWPROC:
		var event newprocEvent
		err = binary.Read(readSeeker, byteOrder, &event)
		if err != nil {
			break
		}
		file, line, fn := interpreter.PCToLine(event.PC)
		if fn == nil {
			log.Fatalf("Read newproc event: invalid PC %x", event.PC)
		}
		log.Printf("newproc invoked in goroutine %d (function: %s, file: %s, line: %d)\n", event.CreatorGoid, fn.Name, file, line)
	case EVENT_TYPE_DELAY:
		var event delayEvent
		err = binary.Read(readSeeker, byteOrder, &event)
		if err != nil {
			break
		}
		file, line, fn := interpreter.PCToLine(event.PC)
		if fn == nil {
			log.Fatalf("Read delay event: invalid PC %x", event.PC)
		}
		log.Printf("delaying line %d in function %s in file %s (pc: %x)\n", line, fn.Name, file, event.PC)
	default:
		err = fmt.Errorf("unrecognized event type")
	}

	return err
}
