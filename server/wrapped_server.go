package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// WrappedSlowmoServer is an entry point to invoke the actual SlowmoServer
// through a connector. It's also responsible for executing the middlewares
// (authn, rate limiting, etc.) before forwarding the requests.
type WrappedSlowmoServer struct {
	proto.UnimplementedSlowmoServiceServer
	authenticators map[proto.AuthnChannel]Authenticator
	rateLimiter    RateLimiter
	connector      SlowmoServerConnector
}

type SlowmoServerConnector interface {
	GetCompileAndRunResponseStream(ctx context.Context, req *proto.CompileAndRunRequest) (StreamWithID, error)
	CloseStream(ctx context.Context, streamID string) error
}

type StreamWithID interface {
	Stream() grpc.ServerStreamingClient[proto.CompileAndRunResponse]
	ID() string
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

func NewWrappedSlowmoServer(authenticators map[proto.AuthnChannel]Authenticator, rateLimiter RateLimiter, connector SlowmoServerConnector) proto.SlowmoServiceServer {
	return &WrappedSlowmoServer{
		authenticators: authenticators,
		rateLimiter:    rateLimiter,
		connector:      connector,
	}
}

type userLoginClaim struct {
	jwt.RegisteredClaims
	UserLogin string             `json:"user"`
	Channel   proto.AuthnChannel `json:"channel"`
}

func (server *WrappedSlowmoServer) CompileAndRun(req *proto.CompileAndRunRequest, stream grpc.ServerStreamingServer[proto.CompileAndRunResponse]) error {
	ctx := stream.Context()
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

	streamWithID, err := server.connector.GetCompileAndRunResponseStream(ctx, req)
	if streamWithID != nil && len(streamWithID.ID()) > 0 {
		// Use background context as parent context to close the connector
		// stream so that the cleanup is executed regardless of the status of
		// this request. Also, note that the eventual termination of the
		// instance is guaranteed by setting the max instance run duration.
		defer server.connector.CloseStream(context.Background(), streamWithID.ID())
	}
	if err != nil {
		logging.Logger().Errorf("[CompileAndRun] Error getting response stream from core: %v", err)
		return err
	}
	for {
		compileAndRunResp, err := streamWithID.Stream().Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				logging.Logger().Debug("Finished receiving exec response stream")
				break
			}
			logging.Logger().Errorf("[CompileAndRun] Error receiving compile and run response from stream: %v", err)
			return ErrInternalExecution
		}
		stream.Send(compileAndRunResp)
	}
	return nil
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

const (
	authnHeaderKeyState        = "oauth-state"
	authnHeaderKeySessionToken = "slowmo-session-token"
	envVarKeySigningKey        = "JWT_SIGNING_KEY"
)

var (
	ErrInternalAuthn     = fmt.Errorf("internal authentication error")
	ErrInternalExecution = fmt.Errorf("internal execution error")
	ErrNoAvailableServer = fmt.Errorf("no available server")
	ErrInternalCleanup   = fmt.Errorf("internal cleanup error")
)

func (server *WrappedSlowmoServer) Authn(ctx context.Context, req *proto.AuthnRequest) (*proto.AuthnResponse, error) {
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
