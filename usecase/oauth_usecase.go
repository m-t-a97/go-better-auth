package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/m-t-a97/go-better-auth/domain"
)

// OAuthUseCase handles OAuth authentication
type OAuthUseCase struct {
	userRepo    UserRepository
	accountRepo AccountRepository
	sessionRepo SessionRepository
	providers   map[string]OAuthProvider
	config      *domain.AuthConfig
}

// NewOAuthUseCase creates a new OAuth use case
func NewOAuthUseCase(
	userRepo UserRepository,
	accountRepo AccountRepository,
	sessionRepo SessionRepository,
	config *domain.AuthConfig,
) *OAuthUseCase {
	return &OAuthUseCase{
		userRepo:    userRepo,
		accountRepo: accountRepo,
		sessionRepo: sessionRepo,
		providers:   make(map[string]OAuthProvider),
		config:      config,
	}
}

// RegisterProvider registers an OAuth provider
func (uc *OAuthUseCase) RegisterProvider(provider OAuthProvider) {
	uc.providers[provider.GetProviderID()] = provider
}

// GetAuthURL returns the OAuth authorization URL
func (uc *OAuthUseCase) GetAuthURL(providerID, state, redirectURI string) (string, error) {
	provider, ok := uc.providers[providerID]
	if !ok {
		return "", fmt.Errorf("provider not found: %s", providerID)
	}

	return provider.GetAuthURL(state, redirectURI), nil
}

// HandleCallback handles the OAuth callback
func (uc *OAuthUseCase) HandleCallback(ctx context.Context, providerID, code, redirectURI string) (*domain.SignInEmailOutput, error) {
	provider, ok := uc.providers[providerID]
	if !ok {
		return nil, fmt.Errorf("provider not found: %s", providerID)
	}

	// Exchange code for tokens
	tokens, err := provider.ExchangeCode(ctx, code, redirectURI)
	if err != nil {
		return nil, err
	}

	// Get user info
	userInfo, err := provider.GetUserInfo(ctx, tokens.AccessToken)
	if err != nil {
		return nil, err
	}

	// Find or create user
	user, _, err := uc.findOrCreateOAuthUser(ctx, providerID, userInfo, tokens)
	if err != nil {
		return nil, err
	}

	// Create session
	session := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     GenerateToken(),
		ExpiresAt: time.Now().Add(uc.config.SessionExpiresIn),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := uc.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	return &domain.SignInEmailOutput{
		User:    user,
		Session: session,
	}, nil
}

// RefreshToken refreshes an OAuth access token using the refresh token
func (uc *OAuthUseCase) RefreshToken(ctx context.Context, input *domain.RefreshTokenInput) (*domain.RefreshTokenOutput, error) {
	// Find the account by user ID and provider
	account, err := uc.accountRepo.FindByUserIDAndProvider(ctx, input.UserID, input.Provider)
	if err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}

	if account.RefreshToken == nil || *account.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available for provider: %s", input.Provider)
	}

	// Check if refresh token has expired
	if account.RefreshTokenExpiresAt != nil && time.Now().After(*account.RefreshTokenExpiresAt) {
		return nil, fmt.Errorf("refresh token has expired")
	}

	// Get the provider
	provider, ok := uc.providers[input.Provider]
	if !ok {
		return nil, fmt.Errorf("provider not found: %s", input.Provider)
	}

	// Use the provider's oauth2 config to refresh the token
	var oauth2Config *oauth2.Config
	switch p := provider.(type) {
	case *GoogleProvider:
		oauth2Config = p.config
	case *GitHubProvider:
		oauth2Config = p.config
	case *DiscordProvider:
		oauth2Config = p.config
	case *GenericOAuthProvider:
		oauth2Config = p.config
	default:
		return nil, fmt.Errorf("unsupported provider type for refresh")
	}

	// Create token source with refresh token
	tokenSource := oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: *account.RefreshToken,
		Expiry:       time.Now().Add(-1 * time.Hour), // Force refresh
	})

	// Get new token
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// Update account with new tokens
	account.AccessToken = &newToken.AccessToken
	account.RefreshToken = &newToken.RefreshToken
	account.UpdatedAt = time.Now()

	if newToken.Expiry.After(time.Now()) {
		expiresAt := newToken.Expiry
		account.AccessTokenExpiresAt = &expiresAt
	}

	// For Google, update ID token if available
	if extra, ok := newToken.Extra("id_token").(string); ok {
		account.IDToken = &extra
	}

	// Save updated account
	if err := uc.accountRepo.Update(ctx, account); err != nil {
		return nil, fmt.Errorf("failed to save refreshed tokens: %w", err)
	}

	expiresIn := int64(0)
	if newToken.Expiry.After(time.Now()) {
		expiresIn = int64(time.Until(newToken.Expiry).Seconds())
	}

	idToken := ""
	if account.IDToken != nil {
		idToken = *account.IDToken
	}

	return &domain.RefreshTokenOutput{
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
		IDToken:      idToken,
		ExpiresIn:    expiresIn,
	}, nil
}

func (uc *OAuthUseCase) findOrCreateOAuthUser(ctx context.Context, providerID string, userInfo *domain.OAuthUserInfo, tokens *domain.OAuthTokens) (*domain.User, *domain.Account, error) {
	// Try to find existing account
	account, err := uc.accountRepo.FindByProviderAccountID(ctx, providerID, userInfo.ID)
	if err == nil && account != nil {
		// Account exists, update tokens
		account.AccessToken = &tokens.AccessToken
		account.RefreshToken = &tokens.RefreshToken
		account.IDToken = &tokens.IDToken
		if tokens.ExpiresIn > 0 {
			expiresAt := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
			account.AccessTokenExpiresAt = &expiresAt
		}
		account.Scope = &tokens.Scope
		account.UpdatedAt = time.Now()

		uc.accountRepo.Update(ctx, account)

		// Get user
		user, err := uc.userRepo.FindByID(ctx, account.UserID)
		if err != nil {
			return nil, nil, err
		}

		return user, account, nil
	}

	// Try to find user by email
	user, err := uc.userRepo.FindByEmail(ctx, userInfo.Email)
	if err != nil {
		// Create new user
		user = &domain.User{
			ID:            uuid.New().String(),
			Email:         userInfo.Email,
			Name:          userInfo.Name,
			EmailVerified: userInfo.EmailVerified,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if userInfo.Image != "" {
			user.Image = &userInfo.Image
		}

		if err := uc.userRepo.Create(ctx, user); err != nil {
			return nil, nil, err
		}
	}

	// Create new account
	account = &domain.Account{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		AccountID:    userInfo.ID,
		ProviderId:   providerID,
		AccessToken:  &tokens.AccessToken,
		RefreshToken: &tokens.RefreshToken,
		IDToken:      &tokens.IDToken,
		Scope:        &tokens.Scope,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if tokens.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
		account.AccessTokenExpiresAt = &expiresAt
	}

	if err := uc.accountRepo.Create(ctx, account); err != nil {
		return nil, nil, err
	}

	return user, account, nil
}

// GoogleProvider implements OAuth for Google
type GoogleProvider struct {
	config *oauth2.Config
}

func NewGoogleProvider(clientID, clientSecret, redirectURL string) *GoogleProvider {
	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		},
	}
}

func (p *GoogleProvider) GetProviderID() string {
	return "google"
}

func (p *GoogleProvider) GetAuthURL(state, redirectURI string) string {
	if redirectURI != "" {
		p.config.RedirectURL = redirectURI
	}
	return p.config.AuthCodeURL(state)
}

func (p *GoogleProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*domain.OAuthTokens, error) {
	if redirectURI != "" {
		p.config.RedirectURL = redirectURI
	}

	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	refreshToken := token.RefreshToken
	idToken := ""
	if extra, ok := token.Extra("id_token").(string); ok {
		idToken = extra
	}

	return &domain.OAuthTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ExpiresIn:    int64(time.Until(token.Expiry).Seconds()),
		Scope:        "",
	}, nil
}

func (p *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*domain.OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", body)
	}

	var data struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		EmailVerified bool   `json:"verified_email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &domain.OAuthUserInfo{
		ID:            data.ID,
		Email:         data.Email,
		Name:          data.Name,
		Image:         data.Picture,
		EmailVerified: data.EmailVerified,
	}, nil
}

// GitHubProvider implements OAuth for GitHub
type GitHubProvider struct {
	config *oauth2.Config
}

func NewGitHubProvider(clientID, clientSecret, redirectURL string) *GitHubProvider {
	return &GitHubProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"user:email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
		},
	}
}

func (p *GitHubProvider) GetProviderID() string {
	return "github"
}

func (p *GitHubProvider) GetAuthURL(state, redirectURI string) string {
	if redirectURI != "" {
		p.config.RedirectURL = redirectURI
	}
	return p.config.AuthCodeURL(state)
}

func (p *GitHubProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*domain.OAuthTokens, error) {
	if redirectURI != "" {
		p.config.RedirectURL = redirectURI
	}

	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return &domain.OAuthTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int64(time.Until(token.Expiry).Seconds()),
		Scope:        "",
	}, nil
}

func (p *GitHubProvider) GetUserInfo(ctx context.Context, accessToken string) (*domain.OAuthUserInfo, error) {
	// Get user info
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", body)
	}

	var userData struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return nil, err
	}

	// Get user email
	req, err = http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, err
	}

	email := ""
	emailVerified := false
	for _, e := range emails {
		if e.Primary {
			email = e.Email
			emailVerified = e.Verified
			break
		}
	}

	if email == "" && len(emails) > 0 {
		email = emails[0].Email
		emailVerified = emails[0].Verified
	}

	name := userData.Name
	if name == "" {
		name = userData.Login
	}

	return &domain.OAuthUserInfo{
		ID:            fmt.Sprintf("%d", userData.ID),
		Email:         email,
		Name:          name,
		Image:         userData.AvatarURL,
		EmailVerified: emailVerified,
	}, nil
}

// DiscordProvider implements OAuth for Discord
type DiscordProvider struct {
	config *oauth2.Config
}

func NewDiscordProvider(clientID, clientSecret, redirectURL string) *DiscordProvider {
	return &DiscordProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"identify", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://discord.com/api/oauth2/authorize",
				TokenURL: "https://discord.com/api/oauth2/token",
			},
		},
	}
}

func (p *DiscordProvider) GetProviderID() string {
	return "discord"
}

func (p *DiscordProvider) GetAuthURL(state, redirectURI string) string {
	if redirectURI != "" {
		p.config.RedirectURL = redirectURI
	}
	return p.config.AuthCodeURL(state)
}

func (p *DiscordProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*domain.OAuthTokens, error) {
	if redirectURI != "" {
		p.config.RedirectURL = redirectURI
	}

	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return &domain.OAuthTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int64(time.Until(token.Expiry).Seconds()),
		Scope:        "",
	}, nil
}

func (p *DiscordProvider) GetUserInfo(ctx context.Context, accessToken string) (*domain.OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", body)
	}

	var data struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Avatar   string `json:"avatar"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	avatarURL := ""
	if data.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", data.ID, data.Avatar)
	}

	return &domain.OAuthUserInfo{
		ID:            data.ID,
		Email:         data.Email,
		Name:          data.Username,
		Image:         avatarURL,
		EmailVerified: data.Verified,
	}, nil
}

// GenericOAuthProvider implements a generic OAuth2 provider
type GenericOAuthProvider struct {
	providerID     string
	config         *oauth2.Config
	userInfoURL    string
	userInfoMapper func(map[string]any) *domain.OAuthUserInfo
}

func NewGenericOAuthProvider(
	providerID, clientID, clientSecret, redirectURL, authURL, tokenURL, userInfoURL string,
	scopes []string,
	userInfoMapper func(map[string]any) *domain.OAuthUserInfo,
) *GenericOAuthProvider {
	return &GenericOAuthProvider{
		providerID: providerID,
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		userInfoURL:    userInfoURL,
		userInfoMapper: userInfoMapper,
	}
}

func (p *GenericOAuthProvider) GetProviderID() string {
	return p.providerID
}

func (p *GenericOAuthProvider) GetAuthURL(state, redirectURI string) string {
	if redirectURI != "" {
		p.config.RedirectURL = redirectURI
	}
	opts := []oauth2.AuthCodeOption{}
	return p.config.AuthCodeURL(state, opts...)
}

func (p *GenericOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*domain.OAuthTokens, error) {
	if redirectURI != "" {
		p.config.RedirectURL = redirectURI
	}

	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return &domain.OAuthTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int64(time.Until(token.Expiry).Seconds()),
		Scope:        "",
	}, nil
}

func (p *GenericOAuthProvider) GetUserInfo(ctx context.Context, accessToken string) (*domain.OAuthUserInfo, error) {
	parsedURL, err := url.Parse(p.userInfoURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", body)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if p.userInfoMapper != nil {
		return p.userInfoMapper(data), nil
	}

	// Default mapping
	return &domain.OAuthUserInfo{
		ID:            getStringField(data, "id", "sub"),
		Email:         getStringField(data, "email"),
		Name:          getStringField(data, "name", "username"),
		Image:         getStringField(data, "picture", "avatar_url", "image"),
		EmailVerified: getBoolField(data, "email_verified", "verified"),
	}, nil
}

func getStringField(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := data[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

func getBoolField(data map[string]any, keys ...string) bool {
	for _, key := range keys {
		if val, ok := data[key]; ok {
			if b, ok := val.(bool); ok {
				return b
			}
		}
	}
	return false
}
