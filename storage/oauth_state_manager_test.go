package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/m-t-a97/go-better-auth/domain/account"
)

func TestNewOAuthStateManager(t *testing.T) {
	secret := "test-secret-for-state-manager"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestNewOAuthStateManager_EmptySecret(t *testing.T) {
	manager, err := NewOAuthStateManager("", 10*time.Minute)
	assert.Error(t, err)
	assert.Nil(t, manager)
}

func TestOAuthStateManager_GenerateState(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	state, err := manager.GenerateState(string(account.ProviderGoogle), "/dashboard", "")
	require.NoError(t, err)
	assert.NotEmpty(t, state)
}

func TestOAuthStateManager_GenerateState_WithUserID(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	state, err := manager.GenerateState(string(account.ProviderGoogle), "/dashboard", "user-123")
	require.NoError(t, err)
	assert.NotEmpty(t, state)
}

func TestOAuthStateManager_GenerateState_EmptyProvider(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	state, err := manager.GenerateState("", "/dashboard", "")
	assert.Error(t, err)
	assert.Empty(t, state)
}

func TestOAuthStateManager_ValidateState_Success(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	// Generate state
	encryptedState, err := manager.GenerateState(string(account.ProviderGoogle), "/dashboard", "user-123")
	require.NoError(t, err)

	// Validate state
	validatedState, err := manager.ValidateState(encryptedState)
	require.NoError(t, err)
	assert.Equal(t, string(account.ProviderGoogle), validatedState.ProviderID)
	assert.Equal(t, "/dashboard", validatedState.RedirectTo)
	assert.Equal(t, "user-123", validatedState.UserID)
}

func TestOAuthStateManager_ValidateState_EmptyState(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	validatedState, err := manager.ValidateState("")
	assert.Error(t, err)
	assert.Nil(t, validatedState)
}

func TestOAuthStateManager_ValidateState_InvalidState(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	validatedState, err := manager.ValidateState("invalid-state-data")
	assert.Error(t, err)
	assert.Nil(t, validatedState)
}

func TestOAuthStateManager_ValidateState_ExpiredState(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 100*time.Millisecond) // Very short TTL
	require.NoError(t, err)

	// Generate state
	encryptedState, err := manager.GenerateState(string(account.ProviderGoogle), "/dashboard", "")
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Try to validate expired state
	validatedState, err := manager.ValidateState(encryptedState)
	assert.Error(t, err)
	assert.Nil(t, validatedState)
	assert.Contains(t, err.Error(), "expired")
}

func TestOAuthStateManager_ValidateState_ReplayAttack(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	// Generate state
	encryptedState, err := manager.GenerateState(string(account.ProviderGoogle), "/dashboard", "")
	require.NoError(t, err)

	// Validate state first time (should succeed)
	validatedState, err := manager.ValidateState(encryptedState)
	require.NoError(t, err)
	assert.NotNil(t, validatedState)

	// Try to validate same state again (should fail - replay attack)
	validatedState, err = manager.ValidateState(encryptedState)
	assert.Error(t, err)
	assert.Nil(t, validatedState)
	assert.Contains(t, err.Error(), "replay attack")
}

func TestOAuthStateManager_ValidateState_DifferentSecret(t *testing.T) {
	secret1 := "test-secret-1"
	secret2 := "test-secret-2"

	manager1, err := NewOAuthStateManager(secret1, 10*time.Minute)
	require.NoError(t, err)

	manager2, err := NewOAuthStateManager(secret2, 10*time.Minute)
	require.NoError(t, err)

	// Generate state with manager1
	encryptedState, err := manager1.GenerateState(string(account.ProviderGoogle), "/dashboard", "")
	require.NoError(t, err)

	// Try to validate with manager2 (different secret - should fail)
	validatedState, err := manager2.ValidateState(encryptedState)
	assert.Error(t, err)
	assert.Nil(t, validatedState)
}

func TestOAuthStateManager_CleanupExpiredStates(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 100*time.Millisecond)
	require.NoError(t, err)

	// Generate multiple states
	for i := 0; i < 5; i++ {
		_, err := manager.GenerateState(string(account.ProviderGoogle), "/dashboard", "")
		require.NoError(t, err)
	}

	// Verify states exist
	assert.Equal(t, 5, manager.Count())

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Cleanup expired states
	cleaned := manager.CleanupExpiredStates()
	assert.Equal(t, 5, cleaned)
	assert.Equal(t, 0, manager.Count())
}

func TestOAuthStateManager_Count(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	assert.Equal(t, 0, manager.Count())

	// Generate states
	_, err = manager.GenerateState(string(account.ProviderGoogle), "/dashboard", "")
	require.NoError(t, err)
	assert.Equal(t, 1, manager.Count())

	_, err = manager.GenerateState(string(account.ProviderGitHub), "/profile", "")
	require.NoError(t, err)
	assert.Equal(t, 2, manager.Count())
}

func TestOAuthStateManager_MultipleProviders(t *testing.T) {
	secret := "test-secret"
	manager, err := NewOAuthStateManager(secret, 10*time.Minute)
	require.NoError(t, err)

	providers := []account.ProviderType{
		account.ProviderGoogle,
		account.ProviderGitHub,
		account.ProviderDiscord,
	}

	states := make(map[account.ProviderType]string)

	// Generate state for each provider
	for _, provider := range providers {
		state, err := manager.GenerateState(string(provider), "/dashboard", "")
		require.NoError(t, err)
		states[provider] = state
	}

	// Validate each state
	for provider, state := range states {
		validatedState, err := manager.ValidateState(state)
		require.NoError(t, err)
		assert.Equal(t, string(provider), validatedState.ProviderID)
	}
}
