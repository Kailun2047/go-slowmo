package main

import (
	"log"
	"math/rand"
	"os"
	"runtime/trace"
	"sync"
	"time"
)

func Greet(name string) {
	log.Println("Hello, " + name)
}

func main() {
	f, err := os.Create("trace.out")
	if err != nil {
		log.Fatalf("failed to create trace output file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("failed to close trace file: %v", err)
		}
	}()
	if err := trace.Start(f); err != nil {
		log.Fatalf("failed to start trace: %v", err)
	}
	defer trace.Stop()

	var wg sync.WaitGroup

	startTime := time.Now().UnixMilli()
	defer func() {
		endTime := time.Now().UnixMilli()
		log.Printf("Time elapsed: %d\n", endTime-startTime)
	}()

	names := []string{"Mauro", "Lucas", "Kerem"}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Greet(names[rand.Intn(len(names))])
		}()
		// Greet(names[rand.Intn(len(names))])
	}

	wg.Wait()
}
