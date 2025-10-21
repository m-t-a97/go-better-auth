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

// GoBetterAuth represents the Go Better Auth instance
type GoBetterAuth struct {
	config           *domain.Config
	authUseCase      *usecase.AuthUseCase
	oauthUseCase     *usecase.OAuthUseCase
	userRepo         usecase.UserRepository
	sessionRepo      usecase.SessionRepository
	accountRepo      usecase.AccountRepository
	verificationRepo usecase.VerificationRepository
}

// New creates a new Better Auth instance with comprehensive configuration
func New(config *domain.Config) (*GoBetterAuth, error) {
	// Apply defaults
	config.ApplyDefaults()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Initialize validation
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
	var passwordHasher usecase.PasswordHasher
	if config.EmailAndPassword != nil && config.EmailAndPassword.Password != nil {
		// Use custom password hasher if provided
		passwordHasher = &customPasswordHasher{
			hashFunc:   config.EmailAndPassword.Password.Hash,
			verifyFunc: config.EmailAndPassword.Password.Verify,
		}
	} else {
		// Use default Argon2 hasher
		passwordHasher = usecase.NewArgon2PasswordHasher()
	}

	// Create email sender wrapper
	var emailSender usecase.EmailSender
	if config.EmailVerification != nil || config.EmailAndPassword != nil {
		emailSender = &emailSenderImpl{
			config: config,
		}
	}

	// Create auth use case
	sessionExpiresIn := time.Duration(config.Session.ExpiresIn) * time.Second
	verificationExpiry := time.Duration(config.EmailVerification.ExpiresIn) * time.Second

	requireEmailVerification := false
	autoSignIn := true

	if config.EmailAndPassword != nil {
		requireEmailVerification = config.EmailAndPassword.RequireEmailVerification
		autoSignIn = config.EmailAndPassword.AutoSignIn
	}

	authUseCase := usecase.NewAuthUseCase(
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
		passwordHasher,
		emailSender,
		&domain.AuthConfig{
			BaseURL:                  config.BaseURL,
			SessionExpiresIn:         sessionExpiresIn,
			VerificationTokenExpiry:  verificationExpiry,
			RequireEmailVerification: requireEmailVerification,
			AutoSignIn:               autoSignIn,
		},
	)

	// Create OAuth use case
	oauthUseCase := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&domain.AuthConfig{
			BaseURL:          config.BaseURL,
			SessionExpiresIn: sessionExpiresIn,
		},
	)

	// Register OAuth providers
	if config.SocialProviders != nil {
		if config.SocialProviders.Google != nil {
			provider := usecase.NewGoogleProvider(
				config.SocialProviders.Google.ClientID,
				config.SocialProviders.Google.ClientSecret,
				config.SocialProviders.Google.RedirectURI,
			)
			oauthUseCase.RegisterProvider(provider)
		}

		if config.SocialProviders.GitHub != nil {
			provider := usecase.NewGitHubProvider(
				config.SocialProviders.GitHub.ClientID,
				config.SocialProviders.GitHub.ClientSecret,
				config.SocialProviders.GitHub.RedirectURI,
			)
			oauthUseCase.RegisterProvider(provider)
		}

		if config.SocialProviders.Discord != nil {
			provider := usecase.NewDiscordProvider(
				config.SocialProviders.Discord.ClientID,
				config.SocialProviders.Discord.ClientSecret,
				config.SocialProviders.Discord.RedirectURI,
			)
			oauthUseCase.RegisterProvider(provider)
		}

		// Register generic OAuth providers
		for name, cfg := range config.SocialProviders.Generic {
			provider := usecase.NewGenericOAuthProvider(
				name,
				cfg.ClientID,
				cfg.ClientSecret,
				cfg.RedirectURI,
				cfg.AuthURL,
				cfg.TokenURL,
				cfg.UserInfoURL,
				cfg.Scopes,
				cfg.UserInfoMapper,
			)
			oauthUseCase.RegisterProvider(provider)
		}
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
	secure := false
	if gba.config.Advanced != nil {
		secure = gba.config.Advanced.UseSecureCookies
	}

	manager := sessionauth.NewManager(gba.sessionRepo, gba.userRepo, &sessionauth.ManagerConfig{
		Secure: secure,
	})
	return sessionauth.NewMiddleware(manager)
}

// Handler returns an http.Handler for all authentication endpoints
// This handler implements the standard library http.Handler interface and works with any framework
func (gba *GoBetterAuth) Handler() http.Handler {
	trustedOrigins := []string{}
	if gba.config.TrustedOrigins.StaticOrigins != nil {
		trustedOrigins = gba.config.TrustedOrigins.StaticOrigins
	}

	return httphandler.NewAuthHandler(
		gba.authUseCase,
		gba.oauthUseCase,
		nil, // MFAUseCase not initialized yet
		gba.config.BaseURL,
		trustedOrigins,
	)
}

// customPasswordHasher implements the PasswordHasher interface with custom functions
type customPasswordHasher struct {
	hashFunc   func(password string) (string, error)
	verifyFunc func(password, hash string) bool
}

func (h *customPasswordHasher) Hash(password string) (string, error) {
	return h.hashFunc(password)
}

func (h *customPasswordHasher) Verify(password, hash string) bool {
	return h.verifyFunc(password, hash)
}

// emailSenderImpl implements the EmailSender interface
type emailSenderImpl struct {
	config *domain.Config
}

func (e *emailSenderImpl) SendVerificationEmail(ctx context.Context, email string, token string, url string) error {
	if e.config.EmailVerification == nil || e.config.EmailVerification.SendVerificationEmail == nil {
		return nil
	}

	// Get user from context or create a minimal user object
	user := &domain.User{Email: email}

	return e.config.EmailVerification.SendVerificationEmail(ctx, user, url, token)
}

func (e *emailSenderImpl) SendPasswordResetEmail(ctx context.Context, email string, token string, url string) error {
	if e.config.EmailAndPassword == nil || e.config.EmailAndPassword.SendResetPassword == nil {
		return nil
	}

	// Get user from context or create a minimal user object
	user := &domain.User{Email: email}

	return e.config.EmailAndPassword.SendResetPassword(ctx, user, url, token)
}
