package storage

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
)

// OAuthState represents an OAuth state parameter with metadata
type OAuthState struct {
	State      string    `json:"state"`
	ProviderID string    `json:"provider_id"`
	RedirectTo string    `json:"redirect_to,omitempty"`
	UserID     string    `json:"user_id,omitempty"` // For account linking
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// OAuthStateManager manages OAuth state parameters with CSRF protection
type OAuthStateManager struct {
	cipher *crypto.CipherManager
	ttl    time.Duration
	mu     sync.RWMutex
	states map[string]*OAuthState // For in-memory validation
}

// NewOAuthStateManager creates a new OAuth state manager
func NewOAuthStateManager(secret string, ttl time.Duration) (*OAuthStateManager, error) {
	if secret == "" {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	if ttl <= 0 {
		ttl = 10 * time.Minute // Default TTL
	}

	// Create cipher manager for encryption and signing
	cipher, err := crypto.NewCipherManager(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher manager: %w", err)
	}

	return &OAuthStateManager{
		cipher: cipher,
		ttl:    ttl,
		states: make(map[string]*OAuthState),
	}, nil
}

// GenerateState generates a new signed OAuth state parameter
func (m *OAuthStateManager) GenerateState(providerID string, redirectTo string, userID string) (string, error) {
	if providerID == "" {
		return "", fmt.Errorf("provider_id cannot be empty")
	}

	// Generate random state token
	randomState, err := crypto.GenerateToken(24)
	if err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}

	now := time.Now()
	state := &OAuthState{
		State:      randomState,
		ProviderID: providerID,
		RedirectTo: redirectTo,
		UserID:     userID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(m.ttl),
	}

	// Marshal to JSON
	data, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to marshal state: %w", err)
	}

	// Encrypt and sign the data using cipher manager
	encrypted, err := m.cipher.Encrypt(string(data))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt state: %w", err)
	}

	// Store in memory for validation
	m.mu.Lock()
	m.states[state.State] = state
	m.mu.Unlock()

	// Return the encrypted state
	return encrypted, nil
}

// ValidateState validates an encrypted OAuth state parameter
func (m *OAuthStateManager) ValidateState(encryptedState string) (*OAuthState, error) {
	if encryptedState == "" {
		return nil, fmt.Errorf("state cannot be empty")
	}

	// Decrypt and verify the state
	decrypted, err := m.cipher.Decrypt(encryptedState)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt state: %w", err)
	}

	// Unmarshal the state
	var state OAuthState
	err = json.Unmarshal([]byte(decrypted), &state)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Check expiration
	if time.Now().After(state.ExpiresAt) {
		// Clean up expired state
		m.mu.Lock()
		delete(m.states, state.State)
		m.mu.Unlock()
		return nil, fmt.Errorf("state expired")
	}

	// Verify state exists in our records
	m.mu.RLock()
	storedState, exists := m.states[state.State]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("state not found: possible replay attack")
	}

	// Validate state matches
	if storedState.ProviderID != state.ProviderID {
		return nil, fmt.Errorf("provider mismatch")
	}

	// Clean up used state (one-time use)
	m.mu.Lock()
	delete(m.states, state.State)
	m.mu.Unlock()

	return &state, nil
}

// CleanupExpiredStates removes expired state parameters
func (m *OAuthStateManager) CleanupExpiredStates() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	count := 0

	for stateID, state := range m.states {
		if now.After(state.ExpiresAt) {
			delete(m.states, stateID)
			count++
		}
	}

	return count
}

// Count returns the number of active states
func (m *OAuthStateManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.states)
}
