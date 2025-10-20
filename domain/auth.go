package domain

import (
	"time"
)

// User represents an authenticated user in the system
type User struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Image         *string   `json:"image,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Session represents an active user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token"`
	IPAddress *string   `json:"ip_address,omitempty"`
	UserAgent *string   `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Account represents a user's authentication account (email, social provider, etc.)
type Account struct {
	ID                    string     `json:"id"`
	UserID                string     `json:"user_id"`
	AccountID             string     `json:"account_id"`  // Provider-specific account ID
	ProviderId            string     `json:"provider_id"` // e.g., "credential", "google", "github"
	AccessToken           *string    `json:"access_token,omitempty"`
	RefreshToken          *string    `json:"refresh_token,omitempty"`
	IDToken               *string    `json:"id_token,omitempty"`
	AccessTokenExpiresAt  *time.Time `json:"access_token_expires_at,omitempty"`
	RefreshTokenExpiresAt *time.Time `json:"refresh_token_expires_at,omitempty"`
	Scope                 *string    `json:"scope,omitempty"`
	Password              *string    `json:"password,omitempty"` // Hashed password for credential provider
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// Verification represents a verification token (email verification, password reset)
type Verification struct {
	ID         string    `json:"id"`
	Identifier string    `json:"identifier"`
	Value      string    `json:"value"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// SignInEmailInput represents the input for email signin
type SignInEmailInput struct {
	Email      string  `json:"email"`
	Password   string  `json:"password"`
	RememberMe bool    `json:"remember_me"`
	IPAddress  *string `json:"ip_address"`
	UserAgent  *string `json:"user_agent"`
}

// SignInEmailOutput represents the output of email signin
type SignInEmailOutput struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
}
