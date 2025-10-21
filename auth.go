package gobetterauth

import (
	"fmt"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// Auth represents the main authentication system
type Auth struct {
	config           *domain.Config
	secretGenerator  *crypto.SecretGenerator
	passwordHasher   *crypto.PasswordHasher
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

	// Create the auth instance
	auth := &Auth{
		config:           config,
		secretGenerator:  crypto.NewSecretGenerator(),
		passwordHasher:   crypto.NewPasswordHasher(),
	}

	return auth, nil
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
