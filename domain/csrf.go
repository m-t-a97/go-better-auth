package domain

import (
	"errors"
	"time"
)

// CSRFToken represents a CSRF token pair for double-submit cookie pattern
type CSRFToken struct {
	// Token value to be included in form/header
	Token string
	// Secret value to be stored in cookie
	Secret string
	// Expiration time of the token
	ExpiresAt time.Time
	// Created at
	CreatedAt time.Time
}

// CSRFRepository defines the interface for CSRF token storage operations
type CSRFRepository interface {
	// StoreToken stores a CSRF token and its secret
	StoreToken(token, secret string, expiresAt time.Time) error
	// ValidateToken validates a CSRF token against stored secret
	ValidateToken(token, secret string) (bool, error)
	// DeleteToken deletes expired or used tokens
	DeleteToken(token string) error
	// CleanupExpired removes all expired CSRF tokens
	CleanupExpired() error
}

// CSRF errors
var (
	ErrCSRFTokenMissing  = errors.New("CSRF token is missing")
	ErrCSRFSecretMissing = errors.New("CSRF secret cookie is missing")
	ErrCSRFTokenInvalid  = errors.New("CSRF token is invalid or expired")
	ErrCSRFMismatch      = errors.New("CSRF token does not match the secret")
)
