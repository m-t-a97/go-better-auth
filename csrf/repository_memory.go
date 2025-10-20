package csrf

import (
	"sync"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// InMemoryRepository is an in-memory implementation of CSRFRepository
// Suitable for single-instance deployments. For distributed systems, use a persistent store.
type InMemoryRepository struct {
	mu     sync.RWMutex
	tokens map[string]*storedToken
}

type storedToken struct {
	secret    string
	expiresAt time.Time
}

// NewInMemoryRepository creates a new in-memory CSRF repository
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		tokens: make(map[string]*storedToken),
	}
}

// StoreToken stores a CSRF token and its secret
func (r *InMemoryRepository) StoreToken(token, secret string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tokens[token] = &storedToken{
		secret:    secret,
		expiresAt: expiresAt,
	}

	return nil
}

// ValidateToken validates a CSRF token against stored secret
func (r *InMemoryRepository) ValidateToken(token, secret string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stored, exists := r.tokens[token]
	if !exists {
		return false, domain.ErrCSRFTokenInvalid
	}

	// Check if token has expired
	if time.Now().After(stored.expiresAt) {
		return false, domain.ErrCSRFTokenInvalid
	}

	// Check if secret matches
	if stored.secret != secret {
		return false, domain.ErrCSRFMismatch
	}

	return true, nil
}

// DeleteToken deletes a CSRF token
func (r *InMemoryRepository) DeleteToken(token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.tokens, token)
	return nil
}

// CleanupExpired removes all expired CSRF tokens
func (r *InMemoryRepository) CleanupExpired() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for token, stored := range r.tokens {
		if now.After(stored.expiresAt) {
			delete(r.tokens, token)
		}
	}

	return nil
}
