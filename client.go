package gobetterauth

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/m-t-a97/go-better-auth/adapters/postgres"
	"github.com/m-t-a97/go-better-auth/adapters/sqlite"
	"github.com/m-t-a97/go-better-auth/csrf"
	"github.com/m-t-a97/go-better-auth/domain"
	httphandler "github.com/m-t-a97/go-better-auth/http"
	"github.com/m-t-a97/go-better-auth/sessionauth"
	"github.com/m-t-a97/go-better-auth/usecase"
)

// Config represents the configuration for Better Auth
type Config struct {
	// Database configuration
	Database DatabaseConfig

	// Base URL of your application
	BaseURL string

	// Email and password configuration
	EmailAndPassword EmailPasswordConfig

	// Session configuration
	Session SessionConfig

	// Social providers
	SocialProviders SocialProvidersConfig

	// Advanced configuration
	Advanced AdvancedConfig
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Provider         string // "postgres", "mysql", "sqlite"
	ConnectionString string
	DB               *sql.DB // Optional: provide your own DB connection
}

// EmailPasswordConfig holds email/password auth configuration
type EmailPasswordConfig struct {
	Enabled                  bool
	RequireEmailVerification bool
	AutoSignIn               bool
	SendVerificationEmail    func(email, token, url string) error
	SendPasswordResetEmail   func(email, token, url string) error
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
	UserInfoMapper func(map[string]any) *domain.OAuthUserInfo
}

// AdvancedConfig holds advanced configuration options
type AdvancedConfig struct {
	PasswordHasher usecase.PasswordHasher
	RateLimiting   bool
	TrustedOrigins []string
	SecureCookies  bool
}

// Handlers contains all the HTTP handler functions for framework-agnostic registration
// DEPRECATED: Library should not provide HTTP handlers. Use AuthUseCase() and OAuthUseCase() instead.
type Handlers struct {
	// Deprecated: Use AuthUseCase() to get the use case and implement handlers yourself
	_ struct{}
}

// RoutePatterns contains route pattern strings for reference
type RoutePatterns struct {
	// Authentication
	SignUpEmail string
	SignInEmail string
	SignOut     string
	GetSession  string
	// Email verification
	SendVerificationEmail string
	VerifyEmail           string
	// Password management
	RequestPasswordReset string
	ResetPassword        string
	ChangePassword       string
	// OAuth
	OAuthAuthorize string
	OAuthCallback  string
}

// Middleware contains middleware functions that work with any HTTP framework
// DEPRECATED: Library should not provide middleware.
type Middleware struct {
	// Deprecated
	_ struct{}
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
		config.BaseURL = "http://localhost:3000"
	}

	if config.Session.ExpiresIn == 0 {
		config.Session.ExpiresIn = 7 * 24 * time.Hour
	}

	if config.EmailAndPassword.Enabled && !config.EmailAndPassword.AutoSignIn {
		config.EmailAndPassword.AutoSignIn = true // Default to true
	}

	// Initialize database repositories
	var userRepo usecase.UserRepository
	var sessionRepo usecase.SessionRepository
	var accountRepo usecase.AccountRepository
	var verificationRepo usecase.VerificationRepository
	var db *sql.DB

	if config.Database.DB != nil {
		db = config.Database.DB
	} else {
		var err error
		switch config.Database.Provider {
		case "postgres":
			db, err = sql.Open("postgres", config.Database.ConnectionString)
			if err != nil {
				return nil, err
			}
			if err := db.Ping(); err != nil {
				return nil, err
			}
		case "sqlite":
			adapter, err := sqlite.NewSQLiteAdapter(config.Database.ConnectionString)
			if err != nil {
				return nil, err
			}
			db = adapter.GetDB()

			// Run migrations
			if err := runSQLiteMigrations(db); err != nil {
				return nil, err
			}
		case "mysql":
			// TODO: Implement MySQL adapter
			return nil, &domain.AuthError{
				Code:    "unsupported_database",
				Message: "MySQL provider not yet implemented",
				Status:  500,
			}
		default:
			return nil, &domain.AuthError{
				Code:    "invalid_database",
				Message: "Invalid database provider",
				Status:  500,
			}
		}
	}

	// Create repositories based on provider
	switch config.Database.Provider {
	case "sqlite":
		userRepo = sqlite.NewSQLiteUserRepository(db)
		sessionRepo = sqlite.NewSQLiteSessionRepository(db)
		accountRepo = sqlite.NewSQLiteAccountRepository(db)
		verificationRepo = sqlite.NewSQLiteVerificationRepository(db)
	default:
		// Default to PostgreSQL
		userRepo = postgres.NewPostgresUserRepository(db)
		sessionRepo = postgres.NewPostgresSessionRepository(db)
		accountRepo = postgres.NewPostgresAccountRepository(db)
		verificationRepo = postgres.NewPostgresVerificationRepository(db)
	}

	// Initialize password hasher
	passwordHasher := config.Advanced.PasswordHasher
	if passwordHasher == nil {
		passwordHasher = usecase.NewScryptPasswordHasher()
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

// GetRoutes returns route pattern information for reference
func (ba *GoBetterAuth) GetRoutes() *RoutePatterns {
	return &RoutePatterns{
		// Authentication routes
		SignUpEmail: "POST /api/auth/sign-up/email",
		SignInEmail: "POST /api/auth/sign-in/email",
		SignOut:     "POST /api/auth/sign-out",
		GetSession:  "GET /api/auth/session",
		// Email verification routes
		SendVerificationEmail: "POST /api/auth/send-verification-email",
		VerifyEmail:           "GET /api/auth/verify-email",
		// Password management routes
		RequestPasswordReset: "POST /api/auth/request-password-reset",
		ResetPassword:        "POST /api/auth/reset-password",
		ChangePassword:       "POST /api/auth/change-password",
		// OAuth routes (dynamic)
		OAuthAuthorize: "GET /api/auth/oauth/{provider}",
		OAuthCallback:  "GET /api/auth/oauth/{provider}/callback",
	}
}

// AuthUseCase returns the auth use case for server-side usage
func (ba *GoBetterAuth) AuthUseCase() *usecase.AuthUseCase {
	return ba.authUseCase
}

// OAuthUseCase returns the OAuth use case for server-side usage
func (ba *GoBetterAuth) OAuthUseCase() *usecase.OAuthUseCase {
	return ba.oauthUseCase
}

// Repositories returns the domain repositories
func (ba *GoBetterAuth) Repositories() (
	userRepo usecase.UserRepository,
	sessionRepo usecase.SessionRepository,
	accountRepo usecase.AccountRepository,
	verificationRepo usecase.VerificationRepository,
) {
	return ba.userRepo, ba.sessionRepo, ba.accountRepo, ba.verificationRepo
}

// SessionAuth returns a session authentication middleware
// This middleware can be used to protect routes and authenticate requests
func (ba *GoBetterAuth) SessionAuth() *sessionauth.Middleware {
	manager := sessionauth.NewManager(ba.sessionRepo, ba.userRepo, &sessionauth.ManagerConfig{
		Secure: ba.config.Advanced.SecureCookies,
	})
	return sessionauth.NewMiddleware(manager)
}

// Handler returns an http.Handler for all authentication endpoints
// This handler implements the standard library http.Handler interface and works with any framework
func (ba *GoBetterAuth) Handler() http.Handler {
	return httphandler.NewAuthHandler(
		ba.authUseCase,
		ba.oauthUseCase,
		nil, // MFAUseCase not initialized yet
		ba.config.BaseURL,
		ba.config.Advanced.TrustedOrigins,
	)
}

// emailSenderImpl implements the EmailSender interface
type emailSenderImpl struct {
	sendVerification func(email, token, url string) error
	sendReset        func(email, token, url string) error
}

func (e *emailSenderImpl) SendVerificationEmail(ctx context.Context, email, token, url string) error {
	if e.sendVerification == nil {
		return nil
	}
	return e.sendVerification(email, token, url)
}

func (e *emailSenderImpl) SendPasswordResetEmail(ctx context.Context, email, token, url string) error {
	if e.sendReset == nil {
		return nil
	}
	return e.sendReset(email, token, url)
}

// runSQLiteMigrations runs all necessary SQLite migrations
func runSQLiteMigrations(db *sql.DB) error {
	ctx := context.Background()

	// Run main migrations
	if _, err := db.ExecContext(ctx, sqlite.SQLiteMigrationSQL); err != nil {
		return err
	}

	// Run MFA migrations
	if _, err := db.ExecContext(ctx, sqlite.SQLiteMFAMigrationSQL); err != nil {
		return err
	}

	// Initialize CSRF schema
	csrfRepo := csrf.NewSQLiteRepository(db)
	if err := csrfRepo.InitSchema(ctx); err != nil {
		return err
	}

	return nil
}
