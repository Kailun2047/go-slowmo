package server

import (
	"context"
	"fmt"

	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/grpc"
)

type GoogleComputeEngineConnector struct{}

func (core *GoogleComputeEngineConnector) CompileAndRunResponseStream(ctx context.Context, req *proto.CompileAndRunRequest) (grpc.ServerStreamingClient[proto.CompileAndRunResponse], error) {
	return nil, fmt.Errorf("unimplemented")
}

func NewGoogleComputeEngineConnector() *GoogleComputeEngineConnector {
	return &GoogleComputeEngineConnector{}
}
