package account

import (
	"fmt"
	"time"
)

// ProviderType defines the type of authentication provider
type ProviderType string

const (
	ProviderCredential ProviderType = "credential" // Email/Password
	ProviderGoogle     ProviderType = "google"
	ProviderGitHub     ProviderType = "github"
	ProviderDiscord    ProviderType = "discord"
	ProviderGeneric    ProviderType = "generic" // Generic OAuth2
)

// Account represents a user's authentication account (email, social provider, etc.)
type Account struct {
	ID                    string
	UserID                string
	AccountID             string // Provider-specific account ID
	ProviderID            ProviderType
	AccessToken           *string
	RefreshToken          *string
	IDToken               *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string
	Password              *string // Hashed password for credential provider
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// CreateAccountRequest represents a request to create a new account
type CreateAccountRequest struct {
	UserID       string
	ProviderID   ProviderType
	AccountID    string
	AccessToken  *string
	RefreshToken *string
	IDToken      *string
	Password     *string // For credential provider only
	Scope        *string
}

// UpdateAccountRequest represents a request to update an existing account
type UpdateAccountRequest struct {
	AccessToken           *string
	RefreshToken          *string
	IDToken               *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string
}

// ValidateCreateAccountRequest validates a create account request
func ValidateCreateAccountRequest(req *CreateAccountRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.UserID == "" {
		return fmt.Errorf("user_id cannot be empty")
	}

	if req.ProviderID == "" {
		return fmt.Errorf("provider_id cannot be empty")
	}

	if !isValidProvider(req.ProviderID) {
		return fmt.Errorf("invalid provider: %s", req.ProviderID)
	}

	if req.AccountID == "" {
		return fmt.Errorf("account_id cannot be empty")
	}

	// Credential provider requires password
	if req.ProviderID == ProviderCredential {
		if req.Password == nil || *req.Password == "" {
			return fmt.Errorf("password is required for credential provider")
		}
	} else {
		// OAuth providers require access token
		if req.AccessToken == nil || *req.AccessToken == "" {
			return fmt.Errorf("access_token is required for %s provider", req.ProviderID)
		}
	}

	if req.AccessToken != nil && *req.AccessToken != "" && len(*req.AccessToken) > 5000 {
		return fmt.Errorf("access_token is too long (max 5000 characters)")
	}

	if req.RefreshToken != nil && *req.RefreshToken != "" && len(*req.RefreshToken) > 5000 {
		return fmt.Errorf("refresh_token is too long (max 5000 characters)")
	}

	if req.IDToken != nil && *req.IDToken != "" && len(*req.IDToken) > 5000 {
		return fmt.Errorf("id_token is too long (max 5000 characters)")
	}

	if req.Scope != nil && *req.Scope != "" && len(*req.Scope) > 500 {
		return fmt.Errorf("scope is too long (max 500 characters)")
	}

	return nil
}

// ValidateUpdateAccountRequest validates an update account request
func ValidateUpdateAccountRequest(req *UpdateAccountRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.AccessToken != nil && *req.AccessToken != "" && len(*req.AccessToken) > 5000 {
		return fmt.Errorf("access_token is too long (max 5000 characters)")
	}

	if req.RefreshToken != nil && *req.RefreshToken != "" && len(*req.RefreshToken) > 5000 {
		return fmt.Errorf("refresh_token is too long (max 5000 characters)")
	}

	if req.IDToken != nil && *req.IDToken != "" && len(*req.IDToken) > 5000 {
		return fmt.Errorf("id_token is too long (max 5000 characters)")
	}

	if req.Scope != nil && *req.Scope != "" && len(*req.Scope) > 500 {
		return fmt.Errorf("scope is too long (max 500 characters)")
	}

	return nil
}

// IsTokenExpired checks if the access token has expired
func (a *Account) IsTokenExpired() bool {
	if a.AccessTokenExpiresAt == nil {
		return false
	}
	return time.Now().After(*a.AccessTokenExpiresAt)
}

// IsRefreshTokenExpired checks if the refresh token has expired
func (a *Account) IsRefreshTokenExpired() bool {
	if a.RefreshTokenExpiresAt == nil {
		return false
	}
	return time.Now().After(*a.RefreshTokenExpiresAt)
}

// isValidProvider checks if the provider is valid
func isValidProvider(provider ProviderType) bool {
	switch provider {
	case ProviderCredential, ProviderGoogle, ProviderGitHub, ProviderDiscord, ProviderGeneric:
		return true
	default:
		return false
	}
}

// Repository defines the interface for account data access
type Repository interface {
	// Create creates a new account
	Create(account *Account) error

	// FindByID retrieves an account by ID
	FindByID(id string) (*Account, error)

	// FindByUserIDAndProvider retrieves a user's account for a specific provider
	FindByUserIDAndProvider(userID string, providerID ProviderType) (*Account, error)

	// FindByUserID retrieves all accounts for a user
	FindByUserID(userID string) ([]*Account, error)

	// Update updates an existing account
	Update(account *Account) error

	// Delete deletes an account by ID
	Delete(id string) error

	// DeleteByUserID deletes all accounts for a user
	DeleteByUserID(userID string) error

	// Count returns the total number of accounts
	Count() (int, error)

	// ExistsByID checks if an account exists by ID
	ExistsByID(id string) (bool, error)

	// ExistsByUserIDAndProvider checks if a user has an account with the specified provider
	ExistsByUserIDAndProvider(userID string, providerID ProviderType) (bool, error)
}
