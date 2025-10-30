package server

import (
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/grpc"
)

type ExecServer struct {
	proto.UnimplementedExecServiceServer
}

func NewExecServer() proto.ExecServiceServer {
	return &ExecServer{}
}

func (s *ExecServer) Exec(req *proto.ExecRequest, stream grpc.ServerStreamingServer[proto.ExecResponse]) error {
	return nil
}
