package gobetterauth

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/m-t-a97/go-better-auth/adapter/postgres"
	"github.com/m-t-a97/go-better-auth/adapter/sqlite"
	"github.com/m-t-a97/go-better-auth/domain"
	httphandler "github.com/m-t-a97/go-better-auth/handler"
	repository "github.com/m-t-a97/go-better-auth/repository/auth"
	"github.com/m-t-a97/go-better-auth/sessionauth"
	"github.com/m-t-a97/go-better-auth/usecase"
	"github.com/m-t-a97/go-better-auth/validation"
)

// AdvancedConfig holds advanced configuration options
type AdvancedConfig struct {
	PasswordHasher usecase.PasswordHasher
	RateLimiting   bool
	TrustedOrigins []string
	SecureCookies  bool
}

// Config represents the configuration for Better Auth
type Config struct {
	// Database configuration
	Database domain.DatabaseConfig

	// Base URL of your application
	BaseURL string

	// Email and password configuration
	EmailAndPassword domain.EmailPasswordConfig

	// Session configuration
	Session domain.SessionConfig

	// Social providers
	SocialProviders domain.SocialProvidersConfig

	// Advanced configuration
	Advanced AdvancedConfig
}

// GoBetterAuth represents the Go Better Auth instance
type GoBetterAuth struct {
	config           *Config
	authUseCase      *usecase.AuthUseCase
	oauthUseCase     *usecase.OAuthUseCase
	userRepo         usecase.UserRepository
	sessionRepo      usecase.SessionRepository
	accountRepo      usecase.AccountRepository
	verificationRepo usecase.VerificationRepository
}

// New creates a new Better Auth instance
func New(config *Config) (*GoBetterAuth, error) {
	// Set defaults
	if config.BaseURL == "" {
		config.BaseURL = "http://localhost:8080"
	}

	if config.Session.ExpiresIn == 0 {
		config.Session.ExpiresIn = 7 * 24 * time.Hour
	}

	if config.EmailAndPassword.Enabled && !config.EmailAndPassword.AutoSignIn {
		config.EmailAndPassword.AutoSignIn = true // Default to true
	}

	validation.Init()

	// Initialize database repositories
	var userRepo usecase.UserRepository
	var sessionRepo usecase.SessionRepository
	var accountRepo usecase.AccountRepository
	var verificationRepo usecase.VerificationRepository
	var db *sql.DB

	if config.Database.DB != nil {
		db = config.Database.DB
	} else {
		switch config.Database.Provider {
		case "postgres":
			_, err := postgres.NewPostgresAdapter(config.Database.ConnectionString)
			if err != nil {
				return nil, err
			}
		case "sqlite":
			_, err := sqlite.NewSQLiteAdapter(config.Database.ConnectionString)
			if err != nil {
				return nil, err
			}
			// TODO: MySQL adapter
		default:
			return nil, &domain.AuthError{
				Code:    "unsupported_database",
				Message: "Unsupported database provider",
				Status:  500,
			}
		}
	}

	// Create repositories based on provider
	switch config.Database.Provider {
	case "sqlite":
		userRepo = repository.NewSQLiteUserRepository(db)
		sessionRepo = repository.NewSQLiteSessionRepository(db)
		accountRepo = repository.NewSQLiteAccountRepository(db)
		verificationRepo = repository.NewSQLiteVerificationRepository(db)
	case "postgres":
		userRepo = repository.NewPostgresUserRepository(db)
		sessionRepo = repository.NewPostgresSessionRepository(db)
		accountRepo = repository.NewPostgresAccountRepository(db)
		verificationRepo = repository.NewPostgresVerificationRepository(db)
	default:
		return nil, &domain.AuthError{
			Code:    "invalid_database",
			Message: "Invalid database provider",
			Status:  500,
		}
	}

	// Initialize password hasher
	passwordHasher := config.Advanced.PasswordHasher
	if passwordHasher == nil {
		passwordHasher = usecase.NewArgon2PasswordHasher()
	}

	// Create email sender wrapper
	var emailSender usecase.EmailSender
	if config.EmailAndPassword.SendVerificationEmail != nil || config.EmailAndPassword.SendPasswordResetEmail != nil {
		emailSender = &emailSenderImpl{
			sendVerification: config.EmailAndPassword.SendVerificationEmail,
			sendReset:        config.EmailAndPassword.SendPasswordResetEmail,
		}
	}

	// Create auth use case
	authUseCase := usecase.NewAuthUseCase(
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
		passwordHasher,
		emailSender,
		&domain.AuthConfig{
			BaseURL:                  config.BaseURL,
			SessionExpiresIn:         config.Session.ExpiresIn,
			VerificationTokenExpiry:  24 * time.Hour,
			RequireEmailVerification: config.EmailAndPassword.RequireEmailVerification,
			AutoSignIn:               config.EmailAndPassword.AutoSignIn,
		},
	)

	// Create OAuth use case
	oauthUseCase := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&domain.AuthConfig{
			BaseURL:          config.BaseURL,
			SessionExpiresIn: config.Session.ExpiresIn,
		},
	)

	// Register OAuth providers
	if config.SocialProviders.Google != nil {
		provider := usecase.NewGoogleProvider(
			config.SocialProviders.Google.ClientID,
			config.SocialProviders.Google.ClientSecret,
			config.SocialProviders.Google.RedirectURL,
		)
		oauthUseCase.RegisterProvider(provider)
	}

	if config.SocialProviders.GitHub != nil {
		provider := usecase.NewGitHubProvider(
			config.SocialProviders.GitHub.ClientID,
			config.SocialProviders.GitHub.ClientSecret,
			config.SocialProviders.GitHub.RedirectURL,
		)
		oauthUseCase.RegisterProvider(provider)
	}

	if config.SocialProviders.Discord != nil {
		provider := usecase.NewDiscordProvider(
			config.SocialProviders.Discord.ClientID,
			config.SocialProviders.Discord.ClientSecret,
			config.SocialProviders.Discord.RedirectURL,
		)
		oauthUseCase.RegisterProvider(provider)
	}

	// Register generic OAuth providers
	for name, cfg := range config.SocialProviders.Generic {
		provider := usecase.NewGenericOAuthProvider(
			name,
			cfg.ClientID,
			cfg.ClientSecret,
			cfg.RedirectURL,
			cfg.AuthURL,
			cfg.TokenURL,
			cfg.UserInfoURL,
			cfg.Scopes,
			cfg.UserInfoMapper,
		)
		oauthUseCase.RegisterProvider(provider)
	}

	return &GoBetterAuth{
		config:           config,
		authUseCase:      authUseCase,
		oauthUseCase:     oauthUseCase,
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		accountRepo:      accountRepo,
		verificationRepo: verificationRepo,
	}, nil
}

// AuthUseCase returns the auth use case for server-side usage
func (gba *GoBetterAuth) AuthUseCase() *usecase.AuthUseCase {
	return gba.authUseCase
}

// OAuthUseCase returns the OAuth use case for server-side usage
func (gba *GoBetterAuth) OAuthUseCase() *usecase.OAuthUseCase {
	return gba.oauthUseCase
}

// Repositories returns the domain repositories
func (gba *GoBetterAuth) Repositories() (
	userRepo usecase.UserRepository,
	sessionRepo usecase.SessionRepository,
	accountRepo usecase.AccountRepository,
	verificationRepo usecase.VerificationRepository,
) {
	return gba.userRepo, gba.sessionRepo, gba.accountRepo, gba.verificationRepo
}

// SessionAuth returns a session authentication middleware
// This middleware can be used to protect routes and authenticate requests
func (gba *GoBetterAuth) SessionAuth() *sessionauth.Middleware {
	manager := sessionauth.NewManager(gba.sessionRepo, gba.userRepo, &sessionauth.ManagerConfig{
		Secure: gba.config.Advanced.SecureCookies,
	})
	return sessionauth.NewMiddleware(manager)
}

// Handler returns an http.Handler for all authentication endpoints
// This handler implements the standard library http.Handler interface and works with any framework
func (gba *GoBetterAuth) Handler() http.Handler {
	return httphandler.NewAuthHandler(
		gba.authUseCase,
		gba.oauthUseCase,
		nil, // MFAUseCase not initialized yet
		gba.config.BaseURL,
		gba.config.Advanced.TrustedOrigins,
	)
}

// emailSenderImpl implements the EmailSender interface
type emailSenderImpl struct {
	sendVerification func(email string, token string, url string) error
	sendReset        func(email string, token string, url string) error
}

func (e *emailSenderImpl) SendVerificationEmail(ctx context.Context, email string, token string, url string) error {
	if e.sendVerification == nil {
		return nil
	}
	return e.sendVerification(email, token, url)
}

func (e *emailSenderImpl) SendPasswordResetEmail(ctx context.Context, email string, token string, url string) error {
	if e.sendReset == nil {
		return nil
	}
	return e.sendReset(email, token, url)
}
