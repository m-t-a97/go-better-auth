package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/m-t-a97/go-better-auth/domain/account"
)

// BaseOAuthProvider provides common OAuth2 functionality
type BaseOAuthProvider struct {
	name        account.ProviderType
	config      *oauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

// NewBaseOAuthProvider creates a new base OAuth provider
func NewBaseOAuthProvider(
	name account.ProviderType,
	config *oauth2.Config,
	userInfoURL string,
) *BaseOAuthProvider {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	return &BaseOAuthProvider{
		name:        name,
		config:      config,
		userInfoURL: userInfoURL,
		httpClient:  httpClient,
	}
}

// Name returns the provider name
func (p *BaseOAuthProvider) Name() account.ProviderType {
	return p.name
}

// GetAuthorizationURL returns the URL to redirect the user to for authorization
func (p *BaseOAuthProvider) GetAuthorizationURL(ctx context.Context, state string) (string, error) {
	if state == "" {
		return "", fmt.Errorf("state cannot be empty")
	}

	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// ExchangeCode exchanges an authorization code for tokens
func (p *BaseOAuthProvider) ExchangeCode(ctx context.Context, code string) (*account.OAuthTokens, error) {
	if code == "" {
		return nil, fmt.Errorf("code cannot be empty")
	}

	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return p.tokenToOAuthTokens(token), nil
}

// GetUser retrieves the user profile from the provider
func (p *BaseOAuthProvider) GetUser(ctx context.Context, tokens *account.OAuthTokens) (*account.OAuthUser, error) {
	if tokens == nil {
		return nil, fmt.Errorf("tokens cannot be nil")
	}

	if tokens.AccessToken == "" {
		return nil, fmt.Errorf("access token cannot be empty")
	}

	// Create a token from the access token
	token := &oauth2.Token{
		AccessToken: tokens.AccessToken,
		TokenType:   "Bearer",
	}

	if tokens.AccessTokenExpiresAt != nil {
		token.Expiry = *tokens.AccessTokenExpiresAt
	}

	// Get user info from the provider
	client := p.config.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var rawData map[string]interface{}
	err = json.Unmarshal(body, &rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	user := p.parseUserData(rawData)
	return user, nil
}

// RefreshAccessToken refreshes the access token using the refresh token
func (p *BaseOAuthProvider) RefreshAccessToken(ctx context.Context, refreshToken string) (*account.OAuthTokens, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token cannot be empty")
	}

	token := &oauth2.Token{
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(-time.Hour), // Force refresh
	}

	tokenSource := p.config.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return p.tokenToOAuthTokens(newToken), nil
}

// tokenToOAuthTokens converts oauth2.Token to account.OAuthTokens
func (p *BaseOAuthProvider) tokenToOAuthTokens(token *oauth2.Token) *account.OAuthTokens {
	result := &account.OAuthTokens{
		AccessToken: token.AccessToken,
	}

	// Try to get scope from extra fields
	if scope, ok := token.Extra("scope").(string); ok {
		result.Scope = scope
	}

	if !token.Expiry.IsZero() {
		result.AccessTokenExpiresAt = &token.Expiry
	}

	if refreshToken, ok := token.Extra("refresh_token").(string); ok && refreshToken != "" {
		result.RefreshToken = &refreshToken
	}

	if idToken, ok := token.Extra("id_token").(string); ok && idToken != "" {
		result.IDToken = &idToken
	}

	return result
}

// parseUserData parses raw user data from provider (override in subclasses)
func (p *BaseOAuthProvider) parseUserData(data map[string]interface{}) *account.OAuthUser {
	user := &account.OAuthUser{
		RawData: data,
	}

	// Standard fields
	if id, ok := data["id"].(string); ok {
		user.ID = id
	}
	if sub, ok := data["sub"].(string); ok && user.ID == "" {
		user.ID = sub
	}

	if email, ok := data["email"].(string); ok {
		user.Email = email
	}

	if name, ok := data["name"].(string); ok {
		user.Name = name
	}

	if picture, ok := data["picture"].(string); ok {
		user.Picture = &picture
	}

	return user
}

// BuildAuthCodeURLWith allows building auth code URL with additional parameters
func (p *BaseOAuthProvider) BuildAuthCodeURLWith(state string, params ...oauth2.AuthCodeOption) (string, error) {
	if state == "" {
		return "", fmt.Errorf("state cannot be empty")
	}

	options := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	options = append(options, params...)

	return p.config.AuthCodeURL(state, options...), nil
}

// ValidateState validates that the state parameter matches (basic implementation)
func ValidateOAuthState(expectedState, receivedState string) error {
	if expectedState == "" || receivedState == "" {
		return fmt.Errorf("state cannot be empty")
	}

	if expectedState != receivedState {
		return fmt.Errorf("state mismatch: possible CSRF attack")
	}

	return nil
}

// ParseAuthorizationCodeFromRequest extracts the authorization code and state from the request
func ParseAuthorizationCodeFromRequest(r *http.Request) (code, state string, err error) {
	if err := r.ParseForm(); err != nil {
		return "", "", fmt.Errorf("failed to parse form: %w", err)
	}

	code = r.FormValue("code")
	if code == "" {
		// Check for error response
		errCode := r.FormValue("error")
		if errCode != "" {
			return "", "", fmt.Errorf("authorization error: %s (%s)", errCode, r.FormValue("error_description"))
		}
		return "", "", fmt.Errorf("authorization code not found in response")
	}

	state = r.FormValue("state")
	if state == "" {
		return "", "", fmt.Errorf("state not found in response")
	}

	return code, state, nil
}

// EncodeState encodes a state parameter (can be overridden for signed states)
func EncodeState(state string) (string, error) {
	if state == "" {
		return "", fmt.Errorf("state cannot be empty")
	}

	// URL encode the state
	return url.QueryEscape(state), nil
}

// DecodeState decodes a state parameter (can be overridden for signed states)
func DecodeState(encodedState string) (string, error) {
	if encodedState == "" {
		return "", fmt.Errorf("encoded state cannot be empty")
	}

	// URL decode the state
	state, err := url.QueryUnescape(encodedState)
	if err != nil {
		return "", fmt.Errorf("failed to decode state: %w", err)
	}

	return state, nil
}
