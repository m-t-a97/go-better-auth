package memory

import (
	"fmt"
	"sync"

	"github.com/m-t-a97/go-better-auth/domain/account"
)

// OAuthProviderRegistry implements account.OAuthProviderRegistry
type OAuthProviderRegistry struct {
	mu        sync.RWMutex
	providers map[account.ProviderType]account.OAuthProvider
}

// NewOAuthProviderRegistry creates a new OAuth provider registry
func NewOAuthProviderRegistry() *OAuthProviderRegistry {
	return &OAuthProviderRegistry{
		providers: make(map[account.ProviderType]account.OAuthProvider),
	}
}

// Register registers a new OAuth provider
func (r *OAuthProviderRegistry) Register(provider account.OAuthProvider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	providerName := provider.Name()
	if _, exists := r.providers[providerName]; exists {
		return fmt.Errorf("provider %s already registered", providerName)
	}

	r.providers[providerName] = provider
	return nil
}

// Get retrieves a provider by name
func (r *OAuthProviderRegistry) Get(providerID account.ProviderType) (account.OAuthProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, exists := r.providers[providerID]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerID)
	}

	return provider, nil
}

// List returns all registered providers
func (r *OAuthProviderRegistry) List() []account.ProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]account.ProviderType, 0, len(r.providers))
	for name := range r.providers {
		providers = append(providers, name)
	}

	return providers
}

// Unregister unregisters a provider (useful for testing)
func (r *OAuthProviderRegistry) Unregister(providerID account.ProviderType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[providerID]; !exists {
		return fmt.Errorf("provider %s not found", providerID)
	}

	delete(r.providers, providerID)
	return nil
}
