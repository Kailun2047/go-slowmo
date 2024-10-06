package main

import (
	"log"
	"math/rand"
	"time"
)

//go:noinline
func Greet(name string) {
	log.Println("Hello, " + name)
}

func main() {
	// var wg sync.WaitGroup

	startTime := time.Now().UnixMilli()
	defer func() {
		endTime := time.Now().UnixMilli()
		log.Printf("Time elapsed: %d\n", endTime-startTime)
	}()

	names := []string{"Mauro", "Lucas", "Kerem"}

	for i := 0; i < 5; i++ {
		// wg.Add(1)
		// go func() {
		// 	defer wg.Done()
		// 	Greet(names[rand.Intn(len(names))])
		// }()
		Greet(names[rand.Intn(len(names))])
	}

	// wg.Wait()
}
