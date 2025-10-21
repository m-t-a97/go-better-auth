package domain

import (
	"context"
	"database/sql"
	"net/http"
)

// Config is the main configuration struct for Go Better Auth
type Config struct {
	// AppName is the name of the application
	AppName string

	// BaseURL is the base URL for Better Auth (e.g., "https://example.com")
	// If not set, will check GO_BETTER_AUTH_URL environment variable
	BaseURL string

	// BasePath is the base path for Better Auth routes (default: "/api/auth")
	// Will be overridden if there is a path component within BaseURL
	BasePath string

	// TrustedOrigins is a list of trusted origins for CORS
	// Supports static origins, dynamic origins via function, and wildcard patterns
	TrustedOrigins TrustedOriginsConfig

	// Secret is used for encryption, signing, and hashing
	// If not set, will check GO_BETTER_AUTH_SECRET or AUTH_SECRET environment variables
	// In production, if not set, will throw an error
	Secret string

	// Database configuration
	Database DatabaseConfig

	// EmailVerification configuration
	EmailVerification *EmailVerificationConfig

	// EmailAndPassword authentication configuration
	EmailAndPassword *EmailPasswordConfig

	// SocialProviders configuration
	SocialProviders *SocialProvidersConfig

	// Plugins is a list of Better Auth plugins
	Plugins []Plugin

	// User configuration options
	User *UserConfig

	// Session configuration options
	Session *SessionConfig

	// Account configuration options
	Account *AccountConfig

	// Verification configuration options
	Verification *VerificationConfig

	// RateLimit configuration
	RateLimit *RateLimitOptions

	// Advanced configuration options
	Advanced *AdvancedConfig

	// Logger configuration
	Logger *LoggerConfig

	// DatabaseHooks for lifecycle events
	DatabaseHooks *DatabaseHooksConfig

	// OnAPIError configuration
	OnAPIError *OnAPIErrorConfig

	// Hooks for request lifecycle
	Hooks *HooksConfig

	// DisabledPaths is a list of paths to disable
	DisabledPaths []string
}

// TrustedOriginsConfig can be a static list, dynamic function, or support wildcards
type TrustedOriginsConfig struct {
	// StaticOrigins is a static list of trusted origins
	StaticOrigins []string

	// DynamicOrigins is a function that returns origins dynamically based on the request
	DynamicOrigins func(r *http.Request) []string
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	// Provider is the database option ("sqlite", "postgres")
	Provider string

	// ConnectionString is the database connection string
	ConnectionString string

	// DB is an optional custom database connection
	DB *sql.DB

	// Casing defines the casing strategy for database columns ("camel", "snake")
	Casing string
}

// EmailVerificationConfig holds email verification configuration
type EmailVerificationConfig struct {
	// SendVerificationEmail is a function to send verification emails
	SendVerificationEmail func(ctx context.Context, user *User, url string, token string) error

	// SendOnSignUp automatically sends verification email after sign up (default: false)
	SendOnSignUp bool

	// SendOnSignIn sends verification email on sign in when user's email is not verified (default: false)
	SendOnSignIn bool

	// AutoSignInAfterVerification automatically signs in the user after email verification
	AutoSignInAfterVerification bool

	// ExpiresIn is the number of seconds the verification token is valid for (default: 3600)
	ExpiresIn int
}

// PasswordConfig holds custom password hashing and verification
type PasswordConfig struct {
	// Hash is a custom password hashing function
	Hash func(password string) (string, error)

	// Verify is a custom password verification function
	Verify func(password, hash string) bool
}

// EmailPasswordConfig holds email/password auth configuration
type EmailPasswordConfig struct {
	// Enabled enables email and password authentication (default: false)
	Enabled bool

	// DisableSignUp disables email and password sign up (default: false)
	DisableSignUp bool

	// RequireEmailVerification requires email verification before session creation
	RequireEmailVerification bool

	// MinPasswordLength is the minimum password length (default: 8)
	MinPasswordLength int

	// MaxPasswordLength is the maximum password length (default: 128)
	MaxPasswordLength int

	// AutoSignIn automatically signs in the user after sign up
	AutoSignIn bool

	// SendResetPassword is a function to send reset password emails
	SendResetPassword func(ctx context.Context, user *User, url string, token string) error

	// ResetPasswordTokenExpiresIn is the number of seconds the reset token is valid for (default: 3600)
	ResetPasswordTokenExpiresIn int

	// Password holds custom password hashing and verification functions
	Password *PasswordConfig
}

// SocialProvidersConfig holds social provider configuration
type SocialProvidersConfig struct {
	Google  *GoogleProviderConfig
	GitHub  *GitHubProviderConfig
	Discord *DiscordProviderConfig
}

// GoogleProviderConfig holds Google OAuth configuration
type GoogleProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// GitHubProviderConfig holds GitHub OAuth configuration
type GitHubProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// DiscordProviderConfig holds Discord OAuth configuration
type DiscordProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// Plugin defines the interface for Go Better Auth plugins
type Plugin interface {
	Name() string
	Initialize(config interface{}) error
}

// AdditionalField defines an additional field for a model
type AdditionalField struct {
	Type string
	// Add more field properties as needed
}

// ChangeEmailConfig holds change email configuration
type ChangeEmailConfig struct {
	// Enabled enables the change email feature (default: false)
	Enabled bool

	// SendChangeEmailVerification is a function to send change email verification
	SendChangeEmailVerification func(ctx context.Context, user *User, newEmail string, url string, token string) error
}

// DeleteUserConfig holds user deletion configuration
type DeleteUserConfig struct {
	// Enabled enables the delete user feature (default: false)
	Enabled bool

	// SendDeleteAccountVerification is a function to send delete account verification
	SendDeleteAccountVerification func(ctx context.Context, user *User, url string, token string) error

	// BeforeDelete is called before user deletion
	BeforeDelete func(ctx context.Context, user *User) error

	// AfterDelete is called after user deletion
	AfterDelete func(ctx context.Context, user *User) error
}

// UserConfig holds user configuration options
type UserConfig struct {
	// ModelName is the model name for the user (default: "user")
	ModelName string

	// Fields maps field names to different column names
	Fields map[string]string

	// AdditionalFields defines additional fields for the user table
	AdditionalFields map[string]AdditionalField

	// ChangeEmail configuration
	ChangeEmail *ChangeEmailConfig

	// DeleteUser configuration
	DeleteUser *DeleteUserConfig
}

// CookieCacheConfig holds cookie cache configuration
type CookieCacheConfig struct {
	// Enabled enables caching session in cookie (default: false)
	Enabled bool

	// MaxAge is the cache duration in seconds (default: 300 - 5 minutes)
	MaxAge int
}

// SessionConfig holds session configuration
type SessionConfig struct {
	// ModelName is the model name for the session (default: "session")
	ModelName string

	// Fields maps field names to different column names
	Fields map[string]string

	// ExpiresIn is the expiration time for the session token in seconds (default: 604800 - 7 days)
	ExpiresIn int

	// UpdateAge is how often the session should be refreshed in seconds (default: 86400 - 1 day)
	UpdateAge int

	// DisableSessionRefresh disables session refresh (default: false)
	DisableSessionRefresh bool

	// AdditionalFields defines additional fields for the session table
	AdditionalFields map[string]AdditionalField

	// StoreSessionInDatabase stores session in database when secondary storage is provided (default: false)
	StoreSessionInDatabase bool

	// PreserveSessionInDatabase preserves session records in database when deleted from secondary storage (default: false)
	PreserveSessionInDatabase bool

	// CookieCache enables caching session in cookie
	CookieCache *CookieCacheConfig
}

// AccountLinkingConfig holds account linking configuration
type AccountLinkingConfig struct {
	// Enabled enables account linking (default: false)
	Enabled bool

	// TrustedProviders is a list of trusted providers
	TrustedProviders []string

	// AllowDifferentEmails allows users to link accounts with different email addresses
	AllowDifferentEmails bool

	// AllowUnlinkingAll allows users to unlink all accounts
	AllowUnlinkingAll bool
}

// AccountConfig holds account configuration options
type AccountConfig struct {
	// ModelName is the model name for the account
	ModelName string

	// Fields maps field names to different column names
	Fields map[string]string

	// EncryptOAuthTokens encrypts OAuth tokens before storing them (default: false)
	EncryptOAuthTokens bool

	// UpdateAccountOnSignIn updates account data on sign in with latest data from provider
	UpdateAccountOnSignIn bool

	// AccountLinking configuration
	AccountLinking *AccountLinkingConfig
}

// VerificationConfig holds verification configuration options
type VerificationConfig struct {
	// ModelName is the model name for the verification table
	ModelName string

	// Fields maps field names to different column names
	Fields map[string]string

	// DisableCleanup disables cleaning up expired values when a verification value is fetched
	DisableCleanup bool
}

// RateLimitRule defines a custom rate limit rule
type RateLimitRule struct {
	Window int
	Max    int
}

// RateLimitOptions holds rate limiting configuration options
type RateLimitOptions struct {
	// Enabled enables rate limiting (defaults: true in production, false in development)
	Enabled bool

	// Window is the time window in seconds (default: 10)
	Window int

	// Max is the maximum number of requests allowed within the window (default: 100)
	Max int

	// CustomRules defines custom rate limit rules for specific paths
	CustomRules map[string]RateLimitRule

	// Storage defines the storage type ("memory", "database", "secondary-storage")
	Storage string

	// ModelName is the name of the table for rate limiting if database is used (default: "rateLimit")
	ModelName string
}

// IPAddressConfig holds IP address configuration
type IPAddressConfig struct {
	// IPAddressHeaders is a list of headers to check for IP address
	IPAddressHeaders []string

	// DisableIpTracking disables IP tracking
	DisableIpTracking bool
}

// CrossSubDomainCookiesConfig holds cross subdomain cookie configuration
type CrossSubDomainCookiesConfig struct {
	// Enabled enables cross subdomain cookies
	Enabled bool

	// AdditionalCookies is a list of additional cookies to share across subdomains
	AdditionalCookies []string

	// Domain is the domain for the cookies
	Domain string
}

// CookieAttributes holds cookie attributes
type CookieAttributes struct {
	HTTPOnly bool
	Secure   bool
	SameSite string
	Path     string
	Domain   string
	MaxAge   int
}

// CookieConfig holds cookie configuration
type CookieConfig struct {
	Name       string
	Attributes CookieAttributes
}

// DatabaseAdvancedConfig holds advanced database configuration
type DatabaseAdvancedConfig struct {
	// UseNumberId uses auto-incrementing IDs instead of UUIDs
	UseNumberId bool

	// GenerateId is a custom ID generator function, or false to disable ID generation
	GenerateId interface{} // func(model string, size int) string or false

	// DefaultFindManyLimit is the default limit for findMany queries
	DefaultFindManyLimit int
}

// AdvancedConfig holds advanced configuration options
type AdvancedConfig struct {
	// IPAddress configuration for rate limiting and session tracking
	IPAddress *IPAddressConfig

	// UseSecureCookies uses secure cookies (default: false)
	UseSecureCookies bool

	// DisableCSRFCheck disables trusted origins check (⚠️ security risk)
	DisableCSRFCheck bool

	// CrossSubDomainCookies configures cookies to be shared across subdomains
	CrossSubDomainCookies *CrossSubDomainCookiesConfig

	// Cookies allows customizing cookie names and attributes
	Cookies map[string]CookieConfig

	// DefaultCookieAttributes sets default attributes for all cookies
	DefaultCookieAttributes *CookieAttributes

	// CookiePrefix is a prefix for all cookies
	CookiePrefix string

	// Database holds advanced database configuration
	Database *DatabaseAdvancedConfig
}

// LogLevel defines the log level
type LogLevel string

const (
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelDebug LogLevel = "debug"
)

// LoggerConfig holds logger configuration
type LoggerConfig struct {
	// Disabled disables all logging (default: false)
	Disabled bool

	// DisableColors disables colors in the default logger (default: auto-detected)
	DisableColors bool

	// Level is the minimum log level to display
	Level LogLevel

	// Log is a custom logging function
	Log func(level LogLevel, message string, args ...interface{})
}

// ModelHooks holds before/after hooks for a model
type ModelHooks struct {
	Create *CRUDHooks
	Update *CRUDHooks
}

// CRUDHooks holds before/after hooks for CRUD operations
type CRUDHooks struct {
	Before func(ctx context.Context, data interface{}) (interface{}, error)
	After  func(ctx context.Context, result interface{}) error
}

// DatabaseHooksConfig holds database lifecycle hooks
type DatabaseHooksConfig struct {
	User         *ModelHooks
	Session      *ModelHooks
	Account      *ModelHooks
	Verification *ModelHooks
}

// OnAPIErrorConfig holds API error handling configuration
type OnAPIErrorConfig struct {
	// Throw throws an error on API error (default: false)
	Throw bool

	// OnError is a custom error handler
	OnError func(err error, ctx context.Context)

	// ErrorURL is the URL to redirect to on error (default: "/api/auth/error")
	ErrorURL string
}

// RequestContext holds request context for hooks
type RequestContext struct {
	Path     string
	Method   string
	Request  *http.Request
	Response interface{}
}

// HooksConfig holds request lifecycle hooks
type HooksConfig struct {
	// Before is executed before processing the request
	Before func(ctx *RequestContext) error

	// After is executed after processing the request
	After func(ctx *RequestContext) error
}
