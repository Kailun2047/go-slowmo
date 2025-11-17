package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kailun2047/slowmo/instrumentation"
	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	buildDir = "/tmp/slowmo-builds"
)

func startInstrumentation(bpfProg, targetPath string) (*instrumentation.Instrumentor, *instrumentation.EventReader) {
	flag.Parse()

	interpreter := instrumentation.NewELFInterpreter(targetPath)

	runtimeSchedAddr := interpreter.GetGlobalVariableAddr("runtime.sched")
	allpSliceAddr := interpreter.GetGlobalVariableAddr("runtime.allp")
	waitReasonStringsAddr := interpreter.GetGlobalVariableAddr("runtime.waitReasonStrings")
	instrumentor := instrumentation.NewInstrumentor(
		interpreter,
		bpfProg,
		targetPath,
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[uint64]{
			NameInBPFProg: "runtime_sched_addr",
			Value:         runtimeSchedAddr,
		}),
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[uint64]{
			NameInBPFProg: "allp_slice_addr",
			Value:         allpSliceAddr,
		}),
		instrumentation.WithGlobalVariable(instrumentation.GlobalVariable[uint64]{
			NameInBPFProg: "waitreason_strings_addr",
			Value:         waitReasonStringsAddr,
		}),
	)

	// Parse go functab and write the parsing result into a map to make it
	// available in ebpf program, so that the ebpf program can perform things
	// like callstack unwinding.
	functabMap := instrumentor.GetMap("go_functab")
	funcTab := interpreter.ParseFuncTab()
	for i, funcInfo := range funcTab {
		// Note that for BPF map of array type, there will be max_entry of
		// key-value pairs upon creation of the map. Therefore manipulation of
		// any KV acts as updating an existing entry.
		err := functabMap.Update(uint32(i), funcInfo, ebpf.UpdateExist)
		if err != nil {
			logging.Logger().Fatalf("error writing function info into go_functab map; key: %d, value %+v, error: %v", i, funcInfo, err)
		}
	}

	/* Capturing key events. */
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "newproc",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_newproc"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "schedule",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_schedule"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "gopark",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_gopark"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "ready",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_goready"},
	})

	/* Inspecting goroutine-storing structures. */
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "newproc",
		AttachOffset: instrumentation.AttachOffsetReturns,
		BpfFns:       []string{"go_runq_status"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "execute",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"go_execute"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "goready",
		AttachOffset: instrumentation.AttachOffsetReturns,
		BpfFns:       []string{"go_goready_runq_status"},
	})
	// TODO: inspect globrunq when entering runtime.execute.

	/* Helpers. */
	instrumentor.InstrumentPackage(instrumentation.PackageSpec{
		TargetPkg: "main",
		BpfFns:    []string{"delay"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "retake",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"avoid_preempt"},
	})
	instrumentor.InstrumentFunction(instrumentation.FunctionSpec{
		TargetPkg:    "runtime",
		TargetFn:     "main",
		AttachOffset: instrumentation.AttachOffsetEntry,
		BpfFns:       []string{"get_waitreason_strings"},
	})

	eventReader := instrumentation.NewEventReader(interpreter, instrumentor.GetMap("instrumentor_event"))
	eventReader.Start()
	return instrumentor, eventReader
}

type SlowmoServer struct {
	proto.UnimplementedSlowmoServiceServer
	execServerAddr   string
	execTimeLimitSec int
	authenticators   map[proto.AuthnChannel]Authenticator
	rateLimiter      RateLimiter
}

type Authenticator interface {
	GetAccessToken(ctx context.Context, exchangeCode string) (string, error)
	GetUserIdentity(ctx context.Context, accessToken string) (UserIdentityProvider, error)
}

type UserIdentityProvider interface {
	UserLogin() string
}

type RateLimiter interface {
	CheckGlobalLimit(ctx context.Context) error
	CheckUserLimit(ctx context.Context, user string, channel proto.AuthnChannel) error
}

func NewSlowmoServer(execServerAddr string, execTimeLimitSec int, authenticators map[proto.AuthnChannel]Authenticator, rateLimiter RateLimiter) proto.SlowmoServiceServer {
	return &SlowmoServer{
		execServerAddr:   execServerAddr,
		execTimeLimitSec: execTimeLimitSec,
		authenticators:   authenticators,
		rateLimiter:      rateLimiter,
	}
}

var (
	errCompilation = fmt.Errorf("")
)

type compileError struct {
	errMsg string
}

func (ce compileError) Error() string {
	return ce.errMsg
}

func (ce compileError) Is(target error) bool {
	return target == errCompilation
}

type userLoginClaim struct {
	jwt.RegisteredClaims
	UserLogin string             `json:"user"`
	Channel   proto.AuthnChannel `json:"channel"`
}

func (server *SlowmoServer) CompileAndRun(req *proto.CompileAndRunRequest, stream grpc.ServerStreamingServer[proto.CompileAndRunResponse]) (compileAndRunErr error) {
	ctx := stream.Context()
	if needAuthentication() {
		claim, err := getAuthenticatedUser(stream.Context())
		if err != nil {
			return err
		}
		logging.Logger().Infof("[CompileAndRun] Received request from user [%s] (channel: %v)", claim.UserLogin, claim.Channel)
		err = server.rateLimiter.CheckUserLimit(ctx, claim.UserLogin, claim.Channel)
		if err == nil {
			err = server.rateLimiter.CheckGlobalLimit(ctx)
		}
		if err != nil {
			logging.Logger().Warnf("[CompileAndRun] Rate limit hit for user [%s] (channel: %v)", claim.UserLogin, claim.Channel)
			return err
		}
		// TODO: add session token expiration.
	}

	var (
		internalErr      error
		wg               sync.WaitGroup
		gomaxprocsSentCh = make(chan struct{})
		execStream       grpc.ServerStreamingClient[proto.ExecResponse]
	)

	logging.Logger().Debug("Received CompileAndRun request")
	defer func() {
		if err := recover(); err != nil {
			internalErr = errors.Join(internalErr, fmt.Errorf("panic detected: %v", err))
		}
		if internalErr != nil {
			logging.Logger().Errorf("unexpected error during CompileAndRun (error: %v, program: %s)", internalErr, req.GetSource())
			compileAndRunErr = ErrInternalExecution
		}
	}()

	outName, err := sandboxedBuild(req.GetSource(), *req.GoVersion)
	if err != nil {
		if !errors.Is(err, errCompilation) {
			internalErr = fmt.Errorf("internal error when building the program: %w", err)
		} else {
			errMsg := err.Error()
			stream.Send(&proto.CompileAndRunResponse{
				CompileAndRunOneof: &proto.CompileAndRunResponse_CompileError{
					CompileError: &proto.CompilationError{
						ErrorMessage: &errMsg,
					},
				},
			})
		}
		return
	}
	defer func() {
		err := os.Remove(outName)
		if err != nil {
			logging.Logger().Errorf("Failed to remove temp built output file %s: %v", outName, err)
		}
	}()

	conn, err := grpc.NewClient(server.execServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		internalErr = fmt.Errorf("failed to connect to exec server at %s (error: %w)", server.execServerAddr, err)
		return
	}

	if req.GoVersion == nil {
		compileAndRunErr = fmt.Errorf("missing Go version in request")
		return
	}
	instrumentor, probeEventReader := startInstrumentation(instrumentorProg(*req.GoVersion), outName)
	logging.Logger().Debugf("Instrumentor started for program %s", outName)
	defer instrumentor.Close()

	if server.execTimeLimitSec > 0 {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithDeadline(context.Background(), time.Now().Add(time.Duration(server.execTimeLimitSec)*time.Second))
		defer cancelFunc()
	}
	execClient := proto.NewExecServiceClient(conn)
	execStream, err = execClient.Exec(ctx, &proto.ExecRequest{
		Path: &outName,
	})
	if err != nil {
		internalErr = fmt.Errorf("error requesting exec server at %s (error: %w)", server.execServerAddr, err)
		return
	}
	wg.Add(1)
	go func() {
		defer func() {
			probeEventReader.Close()
			conn.Close()
			wg.Done()
		}()
		for {
			execResp, err := execStream.Recv()
			if errors.Is(err, io.EOF) {
				logging.Logger().Debug("Finished receiving exec response stream")
				return
			}
			if status.Code(err) == codes.DeadlineExceeded {
				// Execution has reached max time limit and the request to
				// downstream exec server is cancelled.
				errMsg := "execution time exceeds limit"
				logging.Logger().Warn(errMsg)
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_RuntimeResult{
						RuntimeResult: &proto.RuntimeResult{
							ErrorMessage: &errMsg,
						},
					},
				})
				return
			}
			if err != nil {
				internalErr = fmt.Errorf("error receiving exec response: %w", err)
				return
			}
			if execResp.GetGomaxprocs() != 0 {
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_Gomaxprocs{
						Gomaxprocs: execResp.GetGomaxprocs(),
					},
				})
				close(gomaxprocsSentCh)
			} else if execResp.GetRuntimeOutput() != nil {
				output := execResp.GetRuntimeOutput().GetOutput()
				if strings.Contains(output, outName) {
					output = strings.ReplaceAll(output, outName, "main")
					execResp.GetRuntimeOutput().Output = &output
				}
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_RuntimeOutput{
						RuntimeOutput: execResp.GetRuntimeOutput(),
					},
				})
			} else if execResp.GetRuntimeResult() != nil {
				stream.Send(&proto.CompileAndRunResponse{
					CompileAndRunOneof: &proto.CompileAndRunResponse_RuntimeResult{
						RuntimeResult: execResp.GetRuntimeResult(),
					},
				})
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Synchronize to make sure gomaxprocs is the first stream message sent.
		<-gomaxprocsSentCh
		for event := range probeEventReader.ProbeEventCh {
			stream.Send(&proto.CompileAndRunResponse{
				CompileAndRunOneof: &proto.CompileAndRunResponse_RunEvent{
					RunEvent: event,
				},
			})
		}
	}()

	wg.Wait()
	logging.Logger().Debug("Finished serving CompileAndRun request")
	return
}

func needAuthentication() bool {
	return len(os.Getenv(envVarKeySigningKey)) > 0
}

func getAuthenticatedUser(ctx context.Context) (*userLoginClaim, error) {
	sessionToken, err := findHeaderInCookies(ctx, authnHeaderKeySessionToken)
	if err != nil {
		return nil, fmt.Errorf("session error: %w", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	token, err := parser.ParseWithClaims(sessionToken, &userLoginClaim{}, func(token *jwt.Token) (any, error) {
		key, err := base64.RawStdEncoding.DecodeString(os.Getenv(envVarKeySigningKey))
		return []byte(key), err
	})
	if err != nil {
		return nil, fmt.Errorf("authentication error: token validation failed (%w)", err)
	}
	if claim, ok := token.Claims.(*userLoginClaim); !ok {
		return nil, fmt.Errorf("authentication error: invalid claim")
	} else {
		return claim, nil
	}
}

func findHeaderInCookies(ctx context.Context, targetKey string) (string, error) {
	var found string
	md, hasMD := metadata.FromIncomingContext(ctx)
	if !hasMD {
		return found, fmt.Errorf("no metadata found")
	}
	cookiesInMD := md["cookie"]
	if len(cookiesInMD) > 0 {
		for _, cookie := range strings.Split(cookiesInMD[0], ";") {
			cookie = strings.TrimSpace(cookie)
			kv := strings.Split(cookie, "=")
			if len(kv) == 2 && kv[0] == targetKey {
				found = kv[1]
				break
			}
		}
	}
	if len(found) == 0 {
		return "", fmt.Errorf("header not found in metadata")
	}
	return found, nil
}

func sandboxedBuild(source, goVersion string) (string, error) {
	tempFile, err := os.CreateTemp(buildDir, "target-*.go")
	if err != nil {
		logging.Logger().Errorf("Failed to create temp file: %v", err)
		return "", err
	}
	tempFile.WriteString(source)
	defer func() {
		tempFile.Close()
		err := os.Remove(tempFile.Name())
		if err != nil {
			logging.Logger().Errorf("Failed to remove temp source file %s: %v", tempFile.Name(), err)
		}
	}()

	outName := strings.TrimSuffix(tempFile.Name(), ".go")
	goBuildCmd := exec.Command("/usr/bin/env", goBin(goVersion), "build", "-gcflags=all=-N -l", "-o", outName, tempFile.Name())
	buf := bytes.Buffer{}
	goBuildCmd.Stdout = &buf
	goBuildCmd.Stderr = &buf
	err = goBuildCmd.Run()
	if err != nil {
		return "", compileError{
			errMsg: buf.String(),
		}
	}
	return outName, nil
}

func instrumentorProg(goVersion string) string {
	return fmt.Sprintf("./instrumentor%s.o", goVersion)
}

func goBin(goVersion string) string {
	return fmt.Sprintf("go%s", goVersion)
}

const (
	authnHeaderKeyState        = "oauth-state"
	authnHeaderKeySessionToken = "slowmo-session-token"
	envVarKeySigningKey        = "JWT_SIGNING_KEY"
)

var (
	ErrInternalAuthn     = fmt.Errorf("internal authentication error")
	ErrInternalExecution = fmt.Errorf("internal execution error")
	ErrNoAvailableServer = fmt.Errorf("no available server")
)

func (server *SlowmoServer) Authn(ctx context.Context, req *proto.AuthnRequest) (*proto.AuthnResponse, error) {
	if req.Params == nil {
		// Set state.
		logging.Logger().Debug("[Authn] Received authn request to set state")
		buf := make([]byte, 32)
		rand.Read(buf)
		encodedState := base64.RawURLEncoding.EncodeToString(buf)
		header := metadata.Pairs(authnHeaderKeyState, encodedState)
		grpc.SetHeader(ctx, header)
		logging.Logger().Debug("[Authn] Finished setting authn state")
		return &proto.AuthnResponse{State: &encodedState}, nil
	}

	logging.Logger().Debug("[Authn] Received authn request to generate session token")
	if req.Params.Code == nil || req.Params.State == nil {
		return nil, fmt.Errorf("invalid authn params")
	}

	// Verify that the state param is consistent with what's set in
	// metadata.
	encodedState, err := findHeaderInCookies(ctx, authnHeaderKeyState)
	if err != nil {
		return nil, fmt.Errorf("state error: %w", err)
	}
	if encodedState != *req.Params.State {
		return nil, fmt.Errorf("inconsistent state")
	}

	// Use authn params to retrieve user identity and generate session token.
	authenticator, ok := server.authenticators[req.Params.Channel]
	if !ok {
		return nil, fmt.Errorf("target authentication method not supported")
	}
	accessToken, err := authenticator.GetAccessToken(ctx, *req.Params.Code)
	if err != nil {
		if !errors.Is(err, ErrInternalAuthn) {
			err = fmt.Errorf("authentication failed: cannot get access token")
		}
		return nil, err
	}
	userIdentity, err := authenticator.GetUserIdentity(ctx, accessToken)
	if err != nil {
		if !errors.Is(err, ErrInternalAuthn) {
			err = fmt.Errorf("authentication failed: cannot get user identity")
		}
		return nil, err
	}

	signedToken, err := generateJWT(userIdentity.UserLogin(), req.Params.Channel)
	if err != nil {
		logging.Logger().Errorf("[Authn] Failed generating session token: %v", err)
		return nil, ErrInternalAuthn
	}
	header := metadata.Pairs(authnHeaderKeySessionToken, signedToken)
	grpc.SetHeader(ctx, header)

	logging.Logger().Infof("[Authn] Finished generating session token for user [%s] (channel: %v)", userIdentity.UserLogin(), req.Params.Channel)
	return &proto.AuthnResponse{}, nil
}

func generateJWT(userLogin string, channel proto.AuthnChannel) (string, error) {
	encodedKey := os.Getenv(envVarKeySigningKey)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user":    userLogin,
		"channel": channel,
	})
	key, err := base64.RawStdEncoding.DecodeString(encodedKey)
	if err != nil {
		return "", err
	}
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
