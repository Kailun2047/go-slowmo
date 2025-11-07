package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/kailun2047/slowmo/server"
)

const (
	oauthAPIAddr               = "https://github.com/login/oauth/access_token"
	userProfileAPIAddr         = "https://api.github.com/user"
	envVarKeyOAuthClientID     = "OAUTH_CLIENT_ID"
	envVarKeyOAuthClientSecret = "OAUTH_CLIENT_SECRET"
)

type GitHubAuthenticator struct {
	authnClient           *http.Client
	createOauthClientOnce sync.Once
	oauthTimeoutMilli     int
}

func NewGitHubAuthenticator(oauthTimeoutMilli int) *GitHubAuthenticator {
	return &GitHubAuthenticator{
		oauthTimeoutMilli: oauthTimeoutMilli,
	}
}

type oauthResult struct {
	AccessToken string `json:"access_token"`
}

type userResult struct {
	Login string `json:"login"`
}

func (u *userResult) UserLogin() string {
	if u == nil {
		return ""
	}
	return u.Login
}

type oauthRequestBody struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
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
		return server.ErrInternalAuthn
	}
	return nil
}

func (gh *GitHubAuthenticator) GetAccessToken(ctx context.Context, exchangeCode string) (string, error) {
	gh.createOauthClientOnce.Do(func() {
		gh.authnClient = &http.Client{
			Timeout: time.Duration(gh.oauthTimeoutMilli) * time.Millisecond,
		}
	})
	url, err := url.Parse(oauthAPIAddr)
	if err != nil {
		log.Printf("[GitHub Authn] Invalid oauth api address %s", oauthAPIAddr)
		return "", server.ErrInternalAuthn
	}
	oauthReqBody := oauthRequestBody{
		ClientID:     os.Getenv(envVarKeyOAuthClientID),
		ClientSecret: os.Getenv(envVarKeyOAuthClientSecret),
		Code:         exchangeCode,
	}
	oauthReqBodyBytes, err := json.Marshal(oauthReqBody)
	if err != nil {
		log.Printf("[GitHub Authn] Error marshaling oauth request body: %v", err)
		return "", server.ErrInternalAuthn
	}
	buf := bytes.NewBuffer(oauthReqBodyBytes)
	oauthReq, err := http.NewRequestWithContext(ctx, "POST", url.String(), buf)
	if err != nil {
		log.Printf("[GitHub Authn] Cannot create oauth request: %v", err)
		return "", server.ErrInternalAuthn
	}
	oauthReq.Header.Add("Accept", "application/json")
	oauthReq.Header.Add("Content-Type", "application/json")
	oauthResp, err := gh.authnClient.Do(oauthReq)
	if err != nil {
		log.Printf("[GitHub Authn] Failed to request oauth service: %v", err)
		return "", server.ErrInternalAuthn
	}
	var oauthRes oauthResult
	err = parseResponse(oauthResp, &oauthRes)
	if err != nil {
		if !errors.Is(err, server.ErrInternalAuthn) {
			err = fmt.Errorf("oauth error: %w", err)
		}
		return "", err
	}
	return oauthRes.AccessToken, nil
}

func (gh *GitHubAuthenticator) GetUserIdentity(ctx context.Context, accessToken string) (server.UserIdentityProvider, error) {
	userReq, err := http.NewRequestWithContext(ctx, "GET", userProfileAPIAddr, nil)
	if err != nil {
		log.Printf("[Authn] Cannot create oauth user request: %v", err)
		return (*userResult)(nil), server.ErrInternalAuthn
	}
	userReq.Header.Add("Accept", "application/vnd.github+json")
	userReq.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	userReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	userResp, err := gh.authnClient.Do(userReq)
	if err != nil {
		log.Printf("[Authn] Cannot create user request: %v", err)
		return (*userResult)(nil), server.ErrInternalAuthn
	}
	var userRes userResult
	err = parseResponse(userResp, &userRes)
	if err != nil {
		log.Printf("[Authn] Error retriving user result: %v", err)
		return (*userResult)(nil), server.ErrInternalAuthn
	}
	return &userRes, nil
}
