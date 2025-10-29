package domain

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/security"
)

// Default configuration values
const (
	DefaultBasePath              = "/api/auth"
	DefaultSessionExpiresIn      = 604800 // 7 days
	DefaultSessionUpdateAge      = 86400  // 1 day
	DefaultMinPasswordLength     = 8
	DefaultMaxPasswordLength     = 128
	DefaultVerificationExpiresIn = 1 * time.Hour
	DefaultResetPasswordExpiry   = 1 * time.Hour
	DefaultRateLimitWindow       = 10
	DefaultRateLimitMax          = 100
	DefaultCookieCacheMaxAge     = 300 // 5 minutes
	DefaultFindManyLimit         = 100
	DefaultSecret                = "go-better-auth-secret-0123456789"
)

// ApplyDefaults applies default values to a Config
func (c *Config) ApplyDefaults() {
	// Apply BaseURL from environment if not set
	if c.BaseURL == "" {
		c.BaseURL = os.Getenv("GO_BETTER_AUTH_URL")
		if c.BaseURL == "" {
			c.BaseURL = "http://localhost:8080"
		}
	}

	// Apply BasePath default
	if c.BasePath == "" {
		c.BasePath = DefaultBasePath
	}

	// Apply Secret from environment if not set
	if c.Secret == "" {
		c.Secret = os.Getenv("GO_BETTER_AUTH_SECRET")
		if c.Secret == "" {
			c.Secret = os.Getenv("AUTH_SECRET")
		}
		if c.Secret == "" {
			// In production, this should error
			if os.Getenv("GO_ENV") == "production" || os.Getenv("ENV") == "production" {
				panic("SECRET is required in production. Set GO_BETTER_AUTH_SECRET or AUTH_SECRET environment variable")
			}
			c.Secret = DefaultSecret
		}
	}

	// Apply Database defaults
	if c.Database.Casing == "" {
		c.Database.Casing = "snake"
	}

	// Apply EmailVerification defaults
	if c.EmailVerification == nil {
		c.EmailVerification = &EmailVerificationConfig{}
	}
	if c.EmailVerification != nil {
		if c.EmailVerification.ExpiresIn == 0 {
			c.EmailVerification.ExpiresIn = DefaultVerificationExpiresIn
		}
	}

	// Apply EmailAndPassword defaults
	if c.EmailAndPassword != nil {
		if c.EmailAndPassword.MinPasswordLength == 0 {
			c.EmailAndPassword.MinPasswordLength = DefaultMinPasswordLength
		}
		if c.EmailAndPassword.MaxPasswordLength == 0 {
			c.EmailAndPassword.MaxPasswordLength = DefaultMaxPasswordLength
		}
		if c.EmailAndPassword.ResetPasswordTokenExpiresIn == 0 {
			c.EmailAndPassword.ResetPasswordTokenExpiresIn = DefaultResetPasswordExpiry
		}
	}

	// Apply User defaults
	if c.User == nil {
		c.User = &UserConfig{}
	}
	if c.User.ModelName == "" {
		c.User.ModelName = "user"
	}
	if c.User.ChangeEmail == nil {
		c.User.ChangeEmail = &ChangeEmailConfig{}
	}
	if c.User.DeleteUser == nil {
		c.User.DeleteUser = &DeleteUserConfig{}
	}

	// Apply Session defaults
	if c.Session == nil {
		c.Session = &SessionConfig{}
	}
	if c.Session.ModelName == "" {
		c.Session.ModelName = "session"
	}
	if c.Session.ExpiresIn == 0 {
		c.Session.ExpiresIn = DefaultSessionExpiresIn
	}
	if c.Session.UpdateAge == 0 {
		c.Session.UpdateAge = DefaultSessionUpdateAge
	}
	if c.Session.CookieCache != nil && c.Session.CookieCache.MaxAge == 0 {
		c.Session.CookieCache.MaxAge = DefaultCookieCacheMaxAge
	}

	// Apply Account defaults
	if c.Account == nil {
		c.Account = &AccountConfig{}
	}
	if c.Account.ModelName == "" {
		c.Account.ModelName = "account"
	}

	// Apply Verification defaults
	if c.Verification == nil {
		c.Verification = &VerificationConfig{}
	}
	if c.Verification.ModelName == "" {
		c.Verification.ModelName = "verification"
	}

	// Apply RateLimit defaults
	if c.RateLimit == nil {
		c.RateLimit = &RateLimitOptions{}
	}
	// Enable rate limiting by default in production
	if os.Getenv("GO_ENV") == "production" || os.Getenv("ENV") == "production" {
		if !c.RateLimit.Enabled {
			c.RateLimit.Enabled = true
		}
	}
	if c.RateLimit.Window == 0 {
		c.RateLimit.Window = DefaultRateLimitWindow
	}
	if c.RateLimit.Max == 0 {
		c.RateLimit.Max = DefaultRateLimitMax
	}
	if c.RateLimit.Algorithm == "" {
		c.RateLimit.Algorithm = "fixed-window"
	}
	if c.RateLimit.Storage == "" {
		c.RateLimit.Storage = "memory"
	}
	if c.RateLimit.ModelName == "" {
		c.RateLimit.ModelName = "rateLimit"
	}

	// Apply BruteForce defaults
	if c.BruteForce == nil {
		c.BruteForce = security.DefaultBruteForceConfig()
	}

	// Apply Advanced defaults
	if c.Advanced == nil {
		c.Advanced = &AdvancedConfig{}
	}
	if c.Advanced.Database == nil {
		c.Advanced.Database = &DatabaseAdvancedConfig{}
	}
	if c.Advanced.Database.DefaultFindManyLimit == 0 {
		c.Advanced.Database.DefaultFindManyLimit = DefaultFindManyLimit
	}

	// Apply Logger defaults
	if c.Logger == nil {
		c.Logger = &LoggerConfig{}
	}
	if c.Logger.Level == "" {
		c.Logger.Level = LogLevelInfo
	}

	// Apply OnAPIError defaults
	if c.OnAPIError == nil {
		c.OnAPIError = &OnAPIErrorConfig{}
	}
	if c.OnAPIError.ErrorURL == "" {
		c.OnAPIError.ErrorURL = "/api/auth/error"
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate required fields
	if c.Database.Provider == "" {
		return &AuthError{
			Code:    "invalid_config",
			Message: "Database.Provider is required",
			Status:  500,
		}
	}

	if c.Database.Provider != "sqlite" && c.Database.Provider != "postgres" {
		return &AuthError{
			Code:    "invalid_config",
			Message: "Database.Provider must be 'sqlite' or 'postgres'",
			Status:  500,
		}
	}

	if c.Database.DB == nil && c.Database.ConnectionString == "" {
		return &AuthError{
			Code:    "invalid_config",
			Message: "Either Database.DB or Database.ConnectionString must be provided",
			Status:  500,
		}
	}

	// Validate password length constraints
	if c.EmailAndPassword != nil {
		if c.EmailAndPassword.MinPasswordLength < 1 {
			return &AuthError{
				Code:    "invalid_config",
				Message: "EmailAndPassword.MinPasswordLength must be at least 1",
				Status:  500,
			}
		}
		if c.EmailAndPassword.MaxPasswordLength < c.EmailAndPassword.MinPasswordLength {
			return &AuthError{
				Code:    "invalid_config",
				Message: "EmailAndPassword.MaxPasswordLength must be greater than or equal to MinPasswordLength",
				Status:  500,
			}
		}
	}

	return nil
}

// IsTrustedOrigin checks if an origin is trusted, supporting wildcard patterns
func (c *Config) IsTrustedOrigin(origin string) bool {
	// Check static origins
	for _, trusted := range c.TrustedOrigins.StaticOrigins {
		if matchOrigin(trusted, origin) {
			return true
		}
	}

	return false
}

// matchOrigin matches an origin against a pattern (supports wildcards)
func matchOrigin(pattern, origin string) bool {
	// Exact match
	if pattern == origin {
		return true
	}

	// Wildcard pattern matching
	if strings.Contains(pattern, "*") {
		return matchWildcard(pattern, origin)
	}

	return false
}

// matchWildcard matches a wildcard pattern
// Supports patterns like:
// - *.example.com
// - https://*.example.com
// - http://*.dev.example.com
func matchWildcard(pattern, str string) bool {
	// Split pattern and string by protocol if present
	var patternProtocol, patternHost string
	var strProtocol, strHost string

	if strings.Contains(pattern, "://") {
		parts := strings.SplitN(pattern, "://", 2)
		patternProtocol = parts[0]
		patternHost = parts[1]
	} else {
		patternHost = pattern
	}

	if strings.Contains(str, "://") {
		parts := strings.SplitN(str, "://", 2)
		strProtocol = parts[0]
		strHost = parts[1]
	} else {
		strHost = str
	}

	// If pattern has protocol, protocols must match
	if patternProtocol != "" && patternProtocol != strProtocol {
		return false
	}

	// Remove port from host if present
	if idx := strings.Index(strHost, ":"); idx != -1 {
		strHost = strHost[:idx]
	}
	if idx := strings.Index(patternHost, ":"); idx != -1 {
		patternHost = patternHost[:idx]
	}

	// Match wildcard in host
	if strings.HasPrefix(patternHost, "*.") {
		suffix := patternHost[1:] // Remove *
		return strings.HasSuffix(strHost, suffix)
	}

	return patternHost == strHost
}

// GenerateSecret generates a random secret key
func GenerateSecret() (string, error) {
	bytes := make([]byte, 30)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
