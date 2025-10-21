package domain

import (
	"database/sql"
	"time"
)

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Provider         string // "postgres", "sqlite"
	ConnectionString string
	DB               *sql.DB // Optional: provide your own DB connection
}

// EmailPasswordConfig holds email/password auth configuration
type EmailPasswordConfig struct {
	Enabled                  bool
	RequireEmailVerification bool
	AutoSignIn               bool
	SendVerificationEmail    func(email string, token string, url string) error
	SendPasswordResetEmail   func(email string, token string, url string) error
}

// SessionConfig holds session configuration
type SessionConfig struct {
	ExpiresIn        time.Duration
	UpdateExpiration bool
}

// SocialProvidersConfig holds social provider configuration
type SocialProvidersConfig struct {
	Google  *GoogleProviderConfig
	GitHub  *GitHubProviderConfig
	Discord *DiscordProviderConfig
	Generic map[string]*GenericOAuthConfig
}

// GoogleProviderConfig holds Google OAuth configuration
type GoogleProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// GitHubProviderConfig holds GitHub OAuth configuration
type GitHubProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// DiscordProviderConfig holds Discord OAuth configuration
type DiscordProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// GenericOAuthConfig holds generic OAuth provider configuration
type GenericOAuthConfig struct {
	ClientID       string
	ClientSecret   string
	RedirectURL    string
	AuthURL        string
	TokenURL       string
	UserInfoURL    string
	Scopes         []string
	UserInfoMapper func(map[string]any) *OAuthUserInfo
}
