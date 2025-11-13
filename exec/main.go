package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"github.com/kailun2047/slowmoexec/server"
	"google.golang.org/grpc"
)

var (
	port    = flag.Int("port", 50052, "port number the server will listen on")
	logMode = flag.String("log_mode", "production", "logging mode (development or production)")
)

func main() {
	flag.Parse()

	logging.InitZapLogger(*logMode)
	defer logging.Logger().Sync()

	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		logging.Logger().Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	proto.RegisterExecServiceServer(grpcServer, server.NewExecServer())
	logging.Logger().Infof("[exec server] Server listening on port %d", *port)
	grpcServer.Serve(lis)
}
