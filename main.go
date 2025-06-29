package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/kailun2047/slowmo/proto"
	"github.com/kailun2047/slowmo/server"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "port number the server will listen on")
)

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	proto.RegisterSlowmoServiceServer(grpcServer, server.NewSlowmoServer())
	grpcServer.Serve(lis)
}
