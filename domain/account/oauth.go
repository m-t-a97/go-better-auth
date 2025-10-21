package account

import (
	"context"
	"time"
)

// OAuthConfig represents OAuth provider configuration
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// OAuthUser represents a user profile from an OAuth provider
type OAuthUser struct {
	ID      string
	Email   string
	Name    string
	Picture *string
	RawData map[string]interface{}
}

// OAuthTokens represents tokens returned from OAuth provider
type OAuthTokens struct {
	AccessToken           string
	RefreshToken          *string
	IDToken               *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 string
}

// OAuthProvider defines the interface for OAuth provider implementations
type OAuthProvider interface {
	// Name returns the provider name (e.g., "google", "github")
	Name() ProviderType

	// GetAuthorizationURL returns the URL to redirect the user to for authorization
	GetAuthorizationURL(ctx context.Context, state string) (string, error)

	// ExchangeCode exchanges an authorization code for tokens
	ExchangeCode(ctx context.Context, code string) (*OAuthTokens, error)

	// GetUser retrieves the user profile from the provider
	GetUser(ctx context.Context, tokens *OAuthTokens) (*OAuthUser, error)

	// RefreshAccessToken refreshes the access token using the refresh token
	RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuthTokens, error)
}

// OAuthProviderRegistry manages OAuth provider implementations
type OAuthProviderRegistry interface {
	// Register registers a new OAuth provider
	Register(provider OAuthProvider) error

	// Get retrieves a provider by name
	Get(providerID ProviderType) (OAuthProvider, error)

	// List returns all registered providers
	List() []ProviderType
}
