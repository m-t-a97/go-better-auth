package memory

import (
	"context"
	"testing"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockOAuthProvider implements account.OAuthProvider for testing
type MockOAuthProvider struct {
	name string
}

func (m *MockOAuthProvider) Name() account.ProviderType {
	return account.ProviderType(m.name)
}

func (m *MockOAuthProvider) GetAuthorizationURL(ctx context.Context, state string) (string, error) {
	return "https://example.com/auth?state=" + state, nil
}

func (m *MockOAuthProvider) ExchangeCode(ctx context.Context, code string) (*account.OAuthTokens, error) {
	return &account.OAuthTokens{
		AccessToken: "access_token_" + code,
	}, nil
}

func (m *MockOAuthProvider) GetUser(ctx context.Context, tokens *account.OAuthTokens) (*account.OAuthUser, error) {
	return &account.OAuthUser{
		ID:    "user_123",
		Email: "user@example.com",
		Name:  "Test User",
	}, nil
}

func (m *MockOAuthProvider) RefreshAccessToken(ctx context.Context, refreshToken string) (*account.OAuthTokens, error) {
	return &account.OAuthTokens{
		AccessToken: "new_access_token",
	}, nil
}

func TestNewOAuthProviderRegistry(t *testing.T) {
	registry := NewOAuthProviderRegistry()
	assert.NotNil(t, registry)
	assert.Empty(t, registry.List())
}

func TestOAuthProviderRegistry_Register(t *testing.T) {
	registry := NewOAuthProviderRegistry()
	provider := &MockOAuthProvider{name: "google"}

	err := registry.Register(provider)
	require.NoError(t, err)

	providers := registry.List()
	assert.Len(t, providers, 1)
	assert.Contains(t, providers, account.ProviderGoogle)
}

func TestOAuthProviderRegistry_Register_Nil(t *testing.T) {
	registry := NewOAuthProviderRegistry()

	err := registry.Register(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider cannot be nil")
}

func TestOAuthProviderRegistry_Register_Duplicate(t *testing.T) {
	registry := NewOAuthProviderRegistry()
	provider := &MockOAuthProvider{name: "google"}

	err := registry.Register(provider)
	require.NoError(t, err)

	// Try to register the same provider again
	err = registry.Register(provider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestOAuthProviderRegistry_Get(t *testing.T) {
	registry := NewOAuthProviderRegistry()
	provider := &MockOAuthProvider{name: "google"}

	err := registry.Register(provider)
	require.NoError(t, err)

	retrieved, err := registry.Get(account.ProviderGoogle)
	require.NoError(t, err)
	assert.Equal(t, provider, retrieved)
}

func TestOAuthProviderRegistry_Get_NotFound(t *testing.T) {
	registry := NewOAuthProviderRegistry()

	retrieved, err := registry.Get(account.ProviderGoogle)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "not found")
}

func TestOAuthProviderRegistry_List(t *testing.T) {
	registry := NewOAuthProviderRegistry()

	provider1 := &MockOAuthProvider{name: "google"}
	provider2 := &MockOAuthProvider{name: "github"}

	err := registry.Register(provider1)
	require.NoError(t, err)

	err = registry.Register(provider2)
	require.NoError(t, err)

	providers := registry.List()
	assert.Len(t, providers, 2)
	assert.Contains(t, providers, account.ProviderGoogle)
	assert.Contains(t, providers, account.ProviderGitHub)
}

func TestOAuthProviderRegistry_MultipleProviders(t *testing.T) {
	registry := NewOAuthProviderRegistry()

	providers := []*MockOAuthProvider{
		{name: "google"},
		{name: "github"},
		{name: "discord"},
	}

	for _, provider := range providers {
		err := registry.Register(provider)
		require.NoError(t, err)
	}

	assert.Len(t, registry.List(), 3)

	// Test retrieving each provider
	for _, provider := range providers {
		retrieved, err := registry.Get(provider.Name())
		require.NoError(t, err)
		assert.Equal(t, provider, retrieved)
	}
}

func TestOAuthProviderRegistry_Unregister(t *testing.T) {
	registry := NewOAuthProviderRegistry()
	provider := &MockOAuthProvider{name: "google"}

	err := registry.Register(provider)
	require.NoError(t, err)

	err = registry.Unregister(account.ProviderGoogle)
	require.NoError(t, err)

	assert.Empty(t, registry.List())

	// Try to get the unregistered provider
	_, err = registry.Get(account.ProviderGoogle)
	assert.Error(t, err)
}

func TestOAuthProviderRegistry_Unregister_NotFound(t *testing.T) {
	registry := NewOAuthProviderRegistry()

	err := registry.Unregister(account.ProviderGoogle)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
