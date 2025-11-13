package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/middleware"
	"github.com/kailun2047/slowmo/proto"
	"github.com/kailun2047/slowmo/server"
	"google.golang.org/grpc"
)

var (
	port              = flag.Int("port", 50051, "port number the server will listen on")
	execServerAddr    = flag.String("exec_server_addr", "localhost:50052", "exec server address")
	execTimeLimitSec  = flag.Int("exec_time_limit", 70, "max time in second the tracee program can execute")
	oauthTimeoutMilli = flag.Int("oauth_timeout", 3000, "timeout for requesting external oauth service")
	logMode           = flag.String("log_mode", "production", "logging mode (development or production)")
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
	authenticators := map[proto.AuthnChannel]server.Authenticator{
		proto.AuthnChannel_GITHUB: middleware.NewGitHubAuthenticator(*oauthTimeoutMilli),
	}
	redisRateLimiter := middleware.NewRedisRateLimiter()
	proto.RegisterSlowmoServiceServer(grpcServer, server.NewSlowmoServer(*execServerAddr, *execTimeLimitSec, authenticators, redisRateLimiter))
	logging.Logger().Infof("Server listening on port %d", *port)
	grpcServer.Serve(lis)
}
