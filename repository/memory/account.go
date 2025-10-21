package memory

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/m-t-a97/go-better-auth/domain/account"
)

// AccountRepository implements an in-memory account repository
type AccountRepository struct {
	mu       sync.RWMutex
	accounts map[string]*account.Account
}

// NewAccountRepository creates a new in-memory account repository
func NewAccountRepository() *AccountRepository {
	return &AccountRepository{
		accounts: make(map[string]*account.Account),
	}
}

// Create creates a new account
func (r *AccountRepository) Create(a *account.Account) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if a == nil {
		return fmt.Errorf("account cannot be nil")
	}

	// Generate ID if not set
	if a.ID == "" {
		a.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	a.CreatedAt = now
	a.UpdatedAt = now

	r.accounts[a.ID] = a
	return nil
}

// FindByID retrieves an account by ID
func (r *AccountRepository) FindByID(id string) (*account.Account, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if a, ok := r.accounts[id]; ok {
		return a, nil
	}

	return nil, fmt.Errorf("account not found")
}

// FindByUserIDAndProvider retrieves a user's account for a specific provider
func (r *AccountRepository) FindByUserIDAndProvider(userID string, providerID account.ProviderType) (*account.Account, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, a := range r.accounts {
		if a.UserID == userID && a.ProviderID == providerID {
			return a, nil
		}
	}

	return nil, fmt.Errorf("account not found")
}

// FindByUserID retrieves all accounts for a user
func (r *AccountRepository) FindByUserID(userID string) ([]*account.Account, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var accounts []*account.Account
	for _, a := range r.accounts {
		if a.UserID == userID {
			accounts = append(accounts, a)
		}
	}

	return accounts, nil
}

// Update updates an existing account
func (r *AccountRepository) Update(a *account.Account) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if a == nil {
		return fmt.Errorf("account cannot be nil")
	}

	if _, ok := r.accounts[a.ID]; !ok {
		return fmt.Errorf("account not found")
	}

	a.UpdatedAt = time.Now()
	r.accounts[a.ID] = a
	return nil
}

// Delete deletes an account by ID
func (r *AccountRepository) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.accounts[id]; !ok {
		return fmt.Errorf("account not found")
	}

	delete(r.accounts, id)
	return nil
}

// DeleteByUserID deletes all accounts for a user
func (r *AccountRepository) DeleteByUserID(userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, a := range r.accounts {
		if a.UserID == userID {
			delete(r.accounts, id)
		}
	}

	return nil
}

// Count returns the total number of accounts
func (r *AccountRepository) Count() (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.accounts), nil
}

// ExistsByID checks if an account exists by ID
func (r *AccountRepository) ExistsByID(id string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.accounts[id]
	return ok, nil
}

// ExistsByUserIDAndProvider checks if a user has an account with the specified provider
func (r *AccountRepository) ExistsByUserIDAndProvider(userID string, providerID account.ProviderType) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, a := range r.accounts {
		if a.UserID == userID && a.ProviderID == providerID {
			return true, nil
		}
	}

	return false, nil
}
