package gobetterauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/adapter"
	"github.com/m-t-a97/go-better-auth/adapter/postgres"
	"github.com/m-t-a97/go-better-auth/adapter/sqlite"
	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/domain/security"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/handler"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
	"github.com/m-t-a97/go-better-auth/middleware"
	"github.com/m-t-a97/go-better-auth/repository/cached"
	"github.com/m-t-a97/go-better-auth/repository/memory"
	"github.com/m-t-a97/go-better-auth/repository/secondary"
	"github.com/m-t-a97/go-better-auth/usecase/auth"
	"github.com/m-t-a97/go-better-auth/usecase/ratelimit"
	"github.com/m-t-a97/go-better-auth/usecase/security_protection"
)

// Auth represents the main authentication system
type Auth struct {
	config          *domain.Config
	secretGenerator *crypto.SecretGenerator
	passwordHasher  *crypto.Argon2PasswordHasher
	cipherManager   *crypto.CipherManager
	adapter         adapter.Adapter
}

// New creates a new instance of the authentication system
func New(config *domain.Config) (*Auth, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Apply defaults to config
	config.ApplyDefaults()

	// Validate configuration
	validationResult := domain.ValidateConfig(config)
	if !validationResult.Valid {
		return nil, fmt.Errorf("invalid configuration: %s", validationResult.Error())
	}

	// Initialize CipherManager from the secret
	var cipherManager *crypto.CipherManager
	if config.Secret != "" {
		cm, err := crypto.NewCipherManager(config.Secret)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher manager: %w", err)
		}
		cipherManager = cm
	}

	// Create database adapter
	dbAdapter, err := createAdapter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter: %w", err)
	}

	// Create the auth instance
	auth := &Auth{
		config:          config,
		secretGenerator: crypto.NewSecretGenerator(),
		passwordHasher:  crypto.NewArgon2PasswordHasher(),
		cipherManager:   cipherManager,
		adapter:         dbAdapter,
	}

	return auth, nil
}

// createAdapter creates the appropriate database adapter based on configuration
// Redis can be configured as secondary storage for sessions and rate limiting,
// but a primary database (sqlite or postgres) is always required.
func createAdapter(cfg *domain.Config) (adapter.Adapter, error) {
	provider := strings.ToLower(cfg.Database.Provider)

	adapterCfg := &adapter.Config{
		DSN:             cfg.Database.ConnectionString,
		MaxOpenConns:    25,   // default connection pool size
		MaxIdleConns:    5,    // default idle connections
		ConnMaxLifetime: 3600, // default 1 hour
		AutoMigrate:     true,
		LogQueries:      false,
	}

	// Create primary adapter
	var primaryAdapter adapter.Adapter
	var err error

	switch provider {
	case "sqlite":
		primaryAdapter, err = sqlite.NewSQLiteAdapter(adapterCfg)
	case "postgres":
		primaryAdapter, err = postgres.NewPostgresAdapter(adapterCfg)
	default:
		return nil, fmt.Errorf("unsupported database provider: %s (must be 'sqlite' or 'postgres')", provider)
	}

	if err != nil {
		return nil, err
	}

	return primaryAdapter, nil
}

// Config returns the configuration
func (a *Auth) Config() *domain.Config {
	return a.config
}

// SecretGenerator returns the secret generator
func (a *Auth) SecretGenerator() *crypto.SecretGenerator {
	return a.secretGenerator
}

// PasswordHasher returns the password hasher
func (a *Auth) PasswordHasher() *crypto.Argon2PasswordHasher {
	return a.passwordHasher
}

// CipherManager returns the cipher manager for encryption and signing
func (a *Auth) CipherManager() *crypto.CipherManager {
	return a.cipherManager
}

// Handler returns an http.Handler that implements all authentication endpoints.
// This handler can be mounted on any HTTP server, including Chi, Echo, and stdlib mux.
// The handler automatically includes CORS middleware configured with the trusted origins.
// If secondary storage is configured, it will be used for session caching and rate limiting.
func (a *Auth) Handler() http.Handler {
	// Get repositories
	userRepo := a.adapter.UserRepository()
	accountRepo := a.adapter.AccountRepository()
	verificationRepo := a.adapter.VerificationRepository()

	// Wrap session repository with caching if secondary storage is available
	var sessionRepo session.Repository
	sessionRepo = a.adapter.SessionRepository()
	if a.config.SecondaryStorage != nil {
		sessionRepo = cached.NewSessionRepository(sessionRepo, a.config.SecondaryStorage)
	}

	// Create the authentication service
	service := auth.NewService(
		a.config,
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
	)

	// Initialize brute force protection if enabled
	if a.config.BruteForce != nil && a.config.BruteForce.Enabled {
		var bruteForceRepo security.BruteForceRepository
		if a.config.BruteForce.UseSecondaryStorage && a.config.SecondaryStorage != nil {
			bruteForceRepo = secondary.NewSecondaryStorageBruteForceRepository(a.config.SecondaryStorage)
		} else {
			bruteForceRepo = memory.NewInMemoryBruteForceRepository()
		}
		bruteForceService := security_protection.NewBruteForceService(bruteForceRepo, a.config.BruteForce)
		service.SetBruteForceService(bruteForceService)
	}

	// Create the base auth handler
	baseHandler := handler.NewAuthHandler(service)

	// Apply rate limiting middleware if configured and secondary storage is available
	var handlerWithMiddleware http.Handler = baseHandler
	if a.config.RateLimit != nil && a.config.RateLimit.Enabled && a.config.SecondaryStorage != nil {
		limiter := ratelimit.NewLimiter(a.config.SecondaryStorage)
		rateLimitMW := middleware.RateLimitMiddleware(a.config, limiter)
		handlerWithMiddleware = rateLimitMW(baseHandler)
	}

	// Wrap with CORS middleware if trusted origins are configured
	if a.config.TrustedOrigins.StaticOrigins != nil || a.config.TrustedOrigins.DynamicOrigins != nil {
		corsMiddleware := middleware.NewCORSMiddleware(&a.config.TrustedOrigins)
		return corsMiddleware.Handler(handlerWithMiddleware)
	}

	return handlerWithMiddleware
}

// authService creates and returns the authentication service
// This is used internally by middleware factory methods
func (a *Auth) authService() *auth.Service {
	// Get repositories
	userRepo := a.adapter.UserRepository()
	accountRepo := a.adapter.AccountRepository()
	verificationRepo := a.adapter.VerificationRepository()

	// Wrap session repository with caching if secondary storage is available
	var sessionRepo session.Repository
	sessionRepo = a.adapter.SessionRepository()
	if a.config.SecondaryStorage != nil {
		sessionRepo = cached.NewSessionRepository(sessionRepo, a.config.SecondaryStorage)
	}

	// Create the authentication service
	service := auth.NewService(
		a.config,
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
	)

	// Initialize brute force protection if enabled
	if a.config.BruteForce != nil && a.config.BruteForce.Enabled {
		var bruteForceRepo security.BruteForceRepository
		if a.config.BruteForce.UseSecondaryStorage && a.config.SecondaryStorage != nil {
			bruteForceRepo = secondary.NewSecondaryStorageBruteForceRepository(a.config.SecondaryStorage)
		} else {
			bruteForceRepo = memory.NewInMemoryBruteForceRepository()
		}
		bruteForceService := security_protection.NewBruteForceService(bruteForceRepo, a.config.BruteForce)
		service.SetBruteForceService(bruteForceService)
	}

	return service
}

// AuthMiddleware returns a ready-to-use authentication middleware
// It validates session tokens and extracts user IDs from requests
// The middleware requires valid authentication (returns 401 if missing or invalid)
func (a *Auth) AuthMiddleware() *middleware.AuthMiddleware {
	return middleware.NewAuthMiddleware(a.authService())
}

// AuthMiddlewareWithCookie returns a ready-to-use authentication middleware with a custom cookie name
// It validates session tokens and extracts user IDs from requests
// The middleware requires valid authentication (returns 401 if missing or invalid)
func (a *Auth) AuthMiddlewareWithCookie(cookieName string) *middleware.AuthMiddleware {
	return middleware.NewAuthMiddlewareWithCookie(a.authService(), cookieName)
}

// OptionalAuthMiddleware returns a ready-to-use optional authentication middleware
// It validates session tokens if present, but doesn't require them
// Requests without tokens or with invalid tokens are still allowed
func (a *Auth) OptionalAuthMiddleware() *middleware.OptionalAuthMiddleware {
	return middleware.NewOptionalAuthMiddleware(a.authService())
}

// OptionalAuthMiddlewareWithCookie returns a ready-to-use optional authentication middleware with a custom cookie name
// It validates session tokens if present, but doesn't require them
func (a *Auth) OptionalAuthMiddlewareWithCookie(cookieName string) *middleware.OptionalAuthMiddleware {
	return middleware.NewOptionalAuthMiddlewareWithCookie(a.authService(), cookieName)
}
