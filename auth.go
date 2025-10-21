package gobetterauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/adapter"
	"github.com/m-t-a97/go-better-auth/adapter/postgres"
	"github.com/m-t-a97/go-better-auth/adapter/sqlite"
	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/handler"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// Auth represents the main authentication system
type Auth struct {
	config          *domain.Config
	secretGenerator *crypto.SecretGenerator
	passwordHasher  *crypto.PasswordHasher
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

	// Create database adapter
	dbAdapter, err := createAdapter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter: %w", err)
	}

	// Create the auth instance
	auth := &Auth{
		config:          config,
		secretGenerator: crypto.NewSecretGenerator(),
		passwordHasher:  crypto.NewPasswordHasher(),
		adapter:         dbAdapter,
	}

	return auth, nil
}

// createAdapter creates the appropriate database adapter based on configuration
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

	switch provider {
	case "sqlite":
		return sqlite.NewSQLiteAdapter(adapterCfg)
	case "postgres":
		return postgres.NewPostgresAdapter(adapterCfg)
	default:
		return nil, fmt.Errorf("unsupported database provider: %s", provider)
	}
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
func (a *Auth) PasswordHasher() *crypto.PasswordHasher {
	return a.passwordHasher
}

// Handler returns an http.Handler that implements all authentication endpoints.
// This handler can be mounted on any HTTP server, including Chi, Echo, and stdlib mux.
// Usage with stdlib:
//
//	http.Handle("/auth/", auth.Handler())
//
// Usage with Chi:
//
//	r.Mount("/auth", http.StripPrefix("/auth", auth.Handler()))
//
// Usage with Echo:
//
//	e.Any("/auth/*", echo.WrapHandler(auth.Handler()))
func (a *Auth) Handler() http.Handler {
	// Create the authentication service with repositories from the adapter
	service := auth.NewService(
		a.adapter.UserRepository(),
		a.adapter.SessionRepository(),
		a.adapter.AccountRepository(),
		a.adapter.VerificationRepository(),
	)

	// Create and return the HTTP handler
	return handler.NewAuthHandler(service)
}
