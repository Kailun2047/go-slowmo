package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/kailun2047/slowmo/proto"
	"github.com/kailun2047/slowmoexec/server"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50052, "port number the server will listen on")
)

func main() {
	flag.Parse()
	log.Default().SetFlags(log.LstdFlags | log.Lmicroseconds)
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	proto.RegisterExecServiceServer(grpcServer, server.NewExecServer())
	log.Print("[exec server] Server listening on port ", *port)
	grpcServer.Serve(lis)
}
