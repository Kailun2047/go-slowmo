package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/middleware"
	"github.com/kailun2047/slowmo/proto"
	"github.com/kailun2047/slowmo/server"
	"google.golang.org/grpc"
)

func main() {
	var (
		port         *int
		logMode      *string
		slowmoServer proto.SlowmoServiceServer
		wrapped      bool
	)

	initWrappedServer := func(args []string) {
		flags := flag.NewFlagSet("wrappedServer", flag.PanicOnError)
		port = flags.Int("port", 50051, "port number the server will listen on")
		logMode = flags.String("log_mode", "production", "logging mode (development or production)")
		oauthTimeoutMilli := flags.Int("oauth_timeout", 3000, "timeout for requesting external oauth service")

		flags.Parse(args)
		slowmoServer = server.NewWrappedSlowmoServer(map[proto.AuthnChannel]server.Authenticator{
			proto.AuthnChannel_GITHUB: middleware.NewGitHubAuthenticator(*oauthTimeoutMilli),
		}, middleware.NewRedisRateLimiter(), server.NewGoogleComputeEngineConnector())
	}
	initServer := func(args []string) {
		flags := flag.NewFlagSet("server", flag.PanicOnError)
		port = flags.Int("port", 50051, "port number the server will listen on")
		logMode = flags.String("log_mode", "production", "logging mode (development or production)")
		execServerAddr := flags.String("exec_server_addr", "exec-server:50052", "exec server address")
		execTimeLimitSec := flags.Int("exec_time_limit", 70, "max time in second the tracee program can execute")

		flags.Parse(args)
		slowmoServer = server.NewSlowmoServer(*execServerAddr, *execTimeLimitSec)
	}
	if len(os.Args) > 1 && os.Args[1] == "-wrapped" {
		initWrappedServer(os.Args[2:])
		wrapped = true
	} else {
		initServer(os.Args[1:])
	}

	logging.InitZapLogger(*logMode)
	defer logging.Logger().Sync()

	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		logging.Logger().Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	proto.RegisterSlowmoServiceServer(grpcServer, slowmoServer)
	logging.Logger().Infow("Server listening for traffic...", "port", *port, "wrapped", wrapped)
	grpcServer.Serve(lis)
}
