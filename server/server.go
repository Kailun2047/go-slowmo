package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kailun2047/slowmo/instrumentation"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	instrumentorProgPath = "./instrumentor.o"
	buildDir             = "/tmp/slowmo-builds"
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
			log.Fatalf("error writing function info into go_functab map; key: %d, value %+v, error: %v", i, funcInfo, err)
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
	execServerAddr        string
	execTimeLimitSec      int
	authnClient           *http.Client
	createOauthClientOnce sync.Once
	oauthTimeoutMilli     int
}

func NewSlowmoServer(execServerAddr string, execTimeLimitSec, oauthTimeoutMilli int) proto.SlowmoServiceServer {
	return &SlowmoServer{
		execServerAddr:    execServerAddr,
		execTimeLimitSec:  execTimeLimitSec,
		oauthTimeoutMilli: oauthTimeoutMilli,
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

type userLoginCliam struct {
	jwt.RegisteredClaims
	UserLogin string `json:"user"`
}

func (server *SlowmoServer) CompileAndRun(req *proto.CompileAndRunRequest, stream grpc.ServerStreamingServer[proto.CompileAndRunResponse]) (compileAndRunErr error) {
	if needAuthentication() {
		user, err := getAuthenticatedUser(stream.Context())
		if err != nil {
			return err
		}
		log.Printf("[CompileAndRun] Received request from user [%s]", user)
	}

	var (
		internalErr      error
		wg               sync.WaitGroup
		gomaxprocsSentCh = make(chan struct{})
		execStream       grpc.ServerStreamingClient[proto.ExecResponse]
	)

	log.Println("Received CompileAndRun request")
	defer func() {
		if err := recover(); err != nil {
			internalErr = errors.Join(internalErr, fmt.Errorf("panic detected: %v", err))
		}
		if internalErr != nil {
			log.Printf("unexpected error during CompileAndRun (error: %v, program: %s)", internalErr, req.GetSource())
			compileAndRunErr = fmt.Errorf("internal error")
		}
	}()

	outName, err := sandboxedBuild(req.GetSource())
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
			log.Printf("Failed to remove temp built output file %s: %v", outName, err)
		}
	}()

	conn, err := grpc.NewClient(server.execServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		internalErr = fmt.Errorf("failed to connect to exec server at %s (error: %w)", server.execServerAddr, err)
		return
	}

	instrumentor, probeEventReader := startInstrumentation(instrumentorProgPath, outName)
	log.Printf("Instrumentor started for program %s", outName)
	defer instrumentor.Close()

	ctx := context.Background()
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
				log.Println("Finished receiving exec response stream")
				return
			}
			if status.Code(err) == codes.DeadlineExceeded {
				// Execution has reached max time limit and the request to
				// downstream exec server is cancelled.
				errMsg := "execution time exceeds limit"
				log.Println(errMsg)
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
	log.Println("Finished serving CompileAndRun request")
	return
}

func needAuthentication() bool {
	return len(os.Getenv(envVarKeyOAuthClientID)) > 0 && len(os.Getenv(envVarKeyOAuthClientSecret)) > 0
}

func getAuthenticatedUser(ctx context.Context) (string, error) {
	sessionToken, err := findHeaderInCookies(ctx, authnHeaderKeySessionToken)
	if err != nil {
		return "", fmt.Errorf("session error: %w", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	token, err := parser.ParseWithClaims(sessionToken, &userLoginCliam{}, func(token *jwt.Token) (any, error) {
		return []byte(os.Getenv(envVarKeySigningKey)), nil
	})
	if err != nil {
		return "", fmt.Errorf("authentication error: token validation failed (%w)", err)
	}
	if claim, ok := token.Claims.(*userLoginCliam); !ok {
		return "", fmt.Errorf("authentication error: invalid claim")
	} else {
		// TODO: rate-limiting for each individual user.
		// TODO: add session token expiration.
		return claim.UserLogin, nil
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

func sandboxedBuild(source string) (string, error) {
	tempFile, err := os.CreateTemp(buildDir, "target-*.go")
	if err != nil {
		log.Printf("Failed to create temp file: %v", err)
		return "", err
	}
	tempFile.WriteString(source)
	defer func() {
		tempFile.Close()
		err := os.Remove(tempFile.Name())
		if err != nil {
			log.Printf("Failed to remove temp source file %s: %v", tempFile.Name(), err)
		}
	}()

	outName := strings.TrimSuffix(tempFile.Name(), ".go")
	goBuildCmd := exec.Command("/usr/bin/env", "go", "build", "-gcflags=all=-N -l", "-o", outName, tempFile.Name())
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

const (
	authnHeaderKeyState        = "oauth-state"
	authnHeaderKeySessionToken = "slowmo-session-token"
	envVarKeySigningKey        = "JWT_SIGNING_KEY"
	envVarKeyOAuthClientID     = "OAUTH_CLIENT_ID"
	envVarKeyOAuthClientSecret = "OAUTH_CLIENT_SECRET"
	oauthAPIAddr               = "https://github.com/login/oauth/access_token"
	userProfileAPIAddr         = "https://api.github.com/user"
)

type oauthResult struct {
	AccessToken string `json:"access_token"`
}

type userResult struct {
	Login string `json:"login"`
}

type oauthRequestBody struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
}

var errInternalAuthn = fmt.Errorf("internal authentication error")

func (server *SlowmoServer) Authn(ctx context.Context, req *proto.AuthnRequest) (*proto.AuthnResponse, error) {
	if req.Params == nil {
		// Set state.
		log.Println("[Authn] Received authn request to set state")
		buf := make([]byte, 32)
		rand.Read(buf)
		encodedState := base64.RawURLEncoding.EncodeToString(buf)
		header := metadata.Pairs(authnHeaderKeyState, encodedState)
		grpc.SetHeader(ctx, header)
		log.Println("[Authn] Finished setting authn state")
		return &proto.AuthnResponse{State: &encodedState}, nil
	}

	log.Println("[Authn] Received authn request to generate session token")
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
	var (
		oauthRes oauthResult
		userRes  userResult
	)
	server.createOauthClientOnce.Do(func() {
		server.authnClient = &http.Client{
			Timeout: time.Duration(server.oauthTimeoutMilli) * time.Millisecond,
		}
	})
	url, err := url.Parse(oauthAPIAddr)
	if err != nil {
		log.Printf("[Authn] Invalid oauth api address %s", oauthAPIAddr)
		return nil, errInternalAuthn
	}
	oauthReqBody := oauthRequestBody{
		ClientID:     os.Getenv(envVarKeyOAuthClientID),
		ClientSecret: os.Getenv(envVarKeyOAuthClientSecret),
		Code:         *req.Params.Code,
	}
	oauthReqBodyBytes, err := json.Marshal(oauthReqBody)
	if err != nil {
		log.Printf("[Authn] Error marshaling oauth request body: %v", err)
		return nil, errInternalAuthn
	}
	buf := bytes.NewBuffer(oauthReqBodyBytes)
	oauthReq, err := http.NewRequestWithContext(ctx, "POST", url.String(), buf)
	if err != nil {
		log.Printf("[Authn] Cannot create oauth request: %v", err)
		return nil, errInternalAuthn
	}
	oauthReq.Header.Add("Accept", "application/json")
	oauthReq.Header.Add("Content-Type", "application/json")
	oauthResp, err := server.authnClient.Do(oauthReq)
	if err != nil {
		log.Printf("[Authn] Failed to request oauth service: %v", err)
		return nil, errInternalAuthn
	}
	err = parseResponse(oauthResp, &oauthRes)
	if err != nil {
		if !errors.Is(err, errInternalAuthn) {
			err = fmt.Errorf("oauth error: %w", err)
		}
		return nil, err
	}
	userReq, err := http.NewRequestWithContext(ctx, "GET", userProfileAPIAddr, nil)
	if err != nil {
		log.Printf("[Authn] Cannot create oauth user request: %v", err)
		return nil, errInternalAuthn
	}
	userReq.Header.Add("Accept", "application/vnd.github+json")
	userReq.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	userReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", oauthRes.AccessToken))
	userResp, err := server.authnClient.Do(userReq)
	if err != nil {
		log.Printf("[Authn] Cannot create user request: %v", err)
		return nil, errInternalAuthn
	}
	err = parseResponse(userResp, &userRes)
	if err != nil {
		log.Printf("[Authn] Error retriving user result: %v", err)
		return nil, errInternalAuthn
	}
	signedToken, err := generateJWT(userRes.Login)
	if err != nil {
		log.Printf("[Authn] Failed generating session token: %v", err)
		return nil, errInternalAuthn
	}
	header := metadata.Pairs(authnHeaderKeySessionToken, signedToken)
	grpc.SetHeader(ctx, header)

	log.Printf("[Authn] Finished generating session token for user [%s]", userRes.Login)
	return &proto.AuthnResponse{}, nil
}

type responseResult interface {
	oauthResult | userResult
}

func parseResponse[T responseResult](resp *http.Response, result *T) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error response: %s", resp.Status)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err == nil {
		err = json.Unmarshal(respBody, result)
	}
	if err != nil {
		return errInternalAuthn
	}
	return nil
}

func generateJWT(userLogin string) (string, error) {
	key := os.Getenv(envVarKeySigningKey)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": userLogin,
	})
	signedToken, err := token.SignedString([]byte(key))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
