package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"

	"github.com/kailun2047/slowmo/proto"
	"github.com/kailun2047/slowmo/server"
	"google.golang.org/grpc"
)

var (
	port       = flag.Int("port", 50051, "port number the server will listen on")
	cpuprofile = flag.String("cpuprofile", "cpu.prof", "write cpu profile to `file`")
)

func main() {
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}
	log.Default().SetFlags(log.LstdFlags | log.Lmicroseconds)
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	proto.RegisterSlowmoServiceServer(grpcServer, server.NewSlowmoServer())
	log.Print("Server listening on port ", *port)
	signalCh := make(chan os.Signal, 5)
	signal.Notify(signalCh, os.Interrupt)
	go func() {
		<-signalCh
		log.Printf("Received SIGINT")
		grpcServer.Stop()
	}()
	err = grpcServer.Serve(lis)
	log.Printf("Error returned by grpcServer.Serve is %v", err)
}
