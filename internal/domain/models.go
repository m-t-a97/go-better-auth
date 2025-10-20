package domain

import (
	"context"
	"time"
)

// User represents an authenticated user in the system
type User struct {
	ID            string
	Name          string
	Email         string
	EmailVerified bool
	Image         *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Session represents an active user session
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	Token     string
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Account represents a user's authentication account (email, social provider, etc.)
type Account struct {
	ID                    string
	UserID                string
	AccountID             string // Provider-specific account ID
	ProviderId            string // e.g., "credential", "google", "github"
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

// Verification represents a verification token (email verification, password reset)
type Verification struct {
	ID         string
	Identifier string // email or user ID
	Value      string // token
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByID(ctx context.Context, id string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
}

// SessionRepository defines the interface for session data operations
type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	FindByToken(ctx context.Context, token string) (*Session, error)
	FindByUserID(ctx context.Context, userID string) ([]*Session, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id string) error
	DeleteByToken(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context) error
}

// AccountRepository defines the interface for account data operations
type AccountRepository interface {
	Create(ctx context.Context, account *Account) error
	FindByUserIDAndProvider(ctx context.Context, userID, providerID string) (*Account, error)
	FindByProviderAccountID(ctx context.Context, providerID, accountID string) (*Account, error)
	Update(ctx context.Context, account *Account) error
	Delete(ctx context.Context, id string) error
	ListByUserID(ctx context.Context, userID string) ([]*Account, error)
}

// VerificationRepository defines the interface for verification token operations
type VerificationRepository interface {
	Create(ctx context.Context, verification *Verification) error
	FindByIdentifierAndValue(ctx context.Context, identifier, value string) (*Verification, error)
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}
