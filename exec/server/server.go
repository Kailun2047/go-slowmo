package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"

	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/grpc"
)

const (
	outputReaderLimit = 1024
)

var gomaxprocs = runtime.GOMAXPROCS(-1)

type ExecServer struct {
	proto.UnimplementedExecServiceServer
}

func NewExecServer() proto.ExecServiceServer {
	return &ExecServer{}
}

func (server *ExecServer) Exec(req *proto.ExecRequest, stream grpc.ServerStreamingServer[proto.ExecResponse]) error {
	var (
		internalErr   error
		finishCh      = make(chan struct{})
		respRunErrMsg *string
	)
	defer func() {
		if internalErr != nil {
			logging.Logger().Errorf("[exec server] Internal error: %v", internalErr)
		}
	}()

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	pipeReader, pipeWriter := io.Pipe()
	runTargetCmd, err := sandboxedRun(ctx, req.GetPath(), pipeWriter)
	if err != nil {
		internalErr = fmt.Errorf("error starting the program: %w", err)
		return internalErr
	} else {
		stream.Send(&proto.ExecResponse{
			ExecOneof: &proto.ExecResponse_Gomaxprocs{
				Gomaxprocs: int32(gomaxprocs),
			},
		})
		go func() {
			defer close(finishCh)
			var (
				n       int
				readErr error
				buf     []byte = make([]byte, outputReaderLimit)
			)
			for readErr == nil {
				n, readErr = pipeReader.Read(buf)
				if n > 0 {
					out := string(buf)
					logging.Logger().Debugf("[exec server] Received new output from program [%s]: [%s]", req.GetPath(), out)
					sendErr := stream.Send(&proto.ExecResponse{
						ExecOneof: &proto.ExecResponse_RuntimeOutput{
							RuntimeOutput: &proto.RuntimeOutput{
								Output: &out,
							},
						},
					})
					if sendErr != nil {
						logging.Logger().Errorf("[exec server] Error when sending runtime output to stream: %v", sendErr)
						// Cancel the command and return upon send error (could
						// be upstream client cancelling request). Note that
						// this doesn't guarantee immediate shutdown when client
						// cancels.
						cancelFunc()
						return
					}
				}
			}
			if !errors.Is(readErr, io.EOF) {
				logging.Logger().Errorf("[exec server] Received error from pipe reader: %v", readErr)
			}
		}()

		runErr := runTargetCmd.Wait()
		pipeWriter.Close()
		<-finishCh
		if runErr != nil {
			runErrMsg := runErr.Error()
			respRunErrMsg = &runErrMsg
		}
		stream.Send(&proto.ExecResponse{
			ExecOneof: &proto.ExecResponse_RuntimeResult{
				RuntimeResult: &proto.RuntimeResult{
					ErrorMessage: respRunErrMsg,
				},
			},
		})
		logging.Logger().Debugf("[exec server] Program %s exited", req.GetPath())
	}

	return nil
}

func sandboxedRun(ctx context.Context, executablePath string, writer io.Writer) (startedCmd *exec.Cmd, err error) {
	logging.Logger().Debugf("[exec server] Start sandbox run of program %s", executablePath)
	runTargetCmd := exec.CommandContext(ctx, executablePath)
	runTargetCmd.Stdout, runTargetCmd.Stderr = writer, writer
	err = runTargetCmd.Start()
	if err == nil {
		startedCmd = runTargetCmd
	}
	return
}
