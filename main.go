package main

import (
	"github.com/kailun2047/slowmo/server"
)

func main() {
	server.StartInstrumentation("instrumentor.o", "target/greet")
}
