package main

import (
	"log"
	"math/rand"
	"sync"
	"time"
)

//go:noinline
func Greet(name string) {
	log.Println("Hello, " + name)
}

func main() {
	var wg sync.WaitGroup

	names := []string{"Mauro", "Lucas", "Kerem"}
	tick := time.Tick(1 * time.Second)
	timeout := time.After(5 * time.Second)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tick:
				Greet(names[rand.Intn(len(names))])
			case <-timeout:
				log.Println("Timeout reached. Returning.")
				return
			}
		}
	}()
	wg.Wait()
}
