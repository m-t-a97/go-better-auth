package mfa

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/m-t-a97/go-better-auth/domain"
)

// InMemoryTwoFactorAuthRepository is an in-memory implementation of TwoFactorAuthRepository
type InMemoryTwoFactorAuthRepository struct {
	mu   sync.RWMutex
	data map[string]*domain.TwoFactorAuth
}

// NewInMemoryTwoFactorAuthRepository creates a new in-memory MFA repository
func NewInMemoryTwoFactorAuthRepository() *InMemoryTwoFactorAuthRepository {
	return &InMemoryTwoFactorAuthRepository{
		data: make(map[string]*domain.TwoFactorAuth),
	}
}

// Create creates a new two-factor auth record
func (r *InMemoryTwoFactorAuthRepository) Create(ctx context.Context, mfa *domain.TwoFactorAuth) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	mfa.ID = uuid.New().String()
	now := time.Now().UTC()
	mfa.CreatedAt = now
	mfa.UpdatedAt = now

	r.data[mfa.ID] = mfa
	return nil
}

// FindByUserID finds a two-factor auth record by user ID
func (r *InMemoryTwoFactorAuthRepository) FindByUserID(ctx context.Context, userID string) (*domain.TwoFactorAuth, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, mfa := range r.data {
		if mfa.UserID == userID {
			return mfa, nil
		}
	}
	return nil, domain.ErrNotFound
}

// FindByUserIDAndMethod finds a two-factor auth record by user ID and method
func (r *InMemoryTwoFactorAuthRepository) FindByUserIDAndMethod(ctx context.Context, userID string, method domain.TwoFactorAuthMethod) (*domain.TwoFactorAuth, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, mfa := range r.data {
		if mfa.UserID == userID && mfa.Method == method {
			return mfa, nil
		}
	}
	return nil, domain.ErrNotFound
}

// Update updates an existing two-factor auth record
func (r *InMemoryTwoFactorAuthRepository) Update(ctx context.Context, mfa *domain.TwoFactorAuth) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.data[mfa.ID]; !exists {
		return domain.ErrNotFound
	}

	mfa.UpdatedAt = time.Now().UTC()
	r.data[mfa.ID] = mfa
	return nil
}

// Delete deletes a two-factor auth record
func (r *InMemoryTwoFactorAuthRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.data[id]; !exists {
		return domain.ErrNotFound
	}

	delete(r.data, id)
	return nil
}

// DeleteByUserID deletes all two-factor auth records for a user
func (r *InMemoryTwoFactorAuthRepository) DeleteByUserID(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, mfa := range r.data {
		if mfa.UserID == userID {
			delete(r.data, id)
		}
	}
	return nil
}

// InMemoryTOTPSecretRepository is an in-memory implementation of TOTPSecretRepository
type InMemoryTOTPSecretRepository struct {
	mu   sync.RWMutex
	data map[string]*domain.TOTPSecret
}

// NewInMemoryTOTPSecretRepository creates a new in-memory TOTP secret repository
func NewInMemoryTOTPSecretRepository() *InMemoryTOTPSecretRepository {
	return &InMemoryTOTPSecretRepository{
		data: make(map[string]*domain.TOTPSecret),
	}
}

// Create creates a new TOTP secret
func (r *InMemoryTOTPSecretRepository) Create(ctx context.Context, secret *domain.TOTPSecret) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	secret.ID = uuid.New().String()
	now := time.Now().UTC()
	secret.CreatedAt = now
	secret.UpdatedAt = now

	r.data[secret.ID] = secret
	return nil
}

// FindByUserID finds a TOTP secret by user ID
func (r *InMemoryTOTPSecretRepository) FindByUserID(ctx context.Context, userID string) (*domain.TOTPSecret, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var latest *domain.TOTPSecret
	for _, secret := range r.data {
		if secret.UserID == userID {
			if latest == nil || secret.CreatedAt.After(latest.CreatedAt) {
				latest = secret
			}
		}
	}

	if latest == nil {
		return nil, domain.ErrNotFound
	}
	return latest, nil
}

// Update updates an existing TOTP secret
func (r *InMemoryTOTPSecretRepository) Update(ctx context.Context, secret *domain.TOTPSecret) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.data[secret.ID]; !exists {
		return domain.ErrNotFound
	}

	secret.UpdatedAt = time.Now().UTC()
	r.data[secret.ID] = secret
	return nil
}

// Delete deletes a TOTP secret
func (r *InMemoryTOTPSecretRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.data[id]; !exists {
		return domain.ErrNotFound
	}

	delete(r.data, id)
	return nil
}

// DeleteByUserID deletes all TOTP secrets for a user
func (r *InMemoryTOTPSecretRepository) DeleteByUserID(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, secret := range r.data {
		if secret.UserID == userID {
			delete(r.data, id)
		}
	}
	return nil
}

// InMemoryMFAChallengeRepository is an in-memory implementation of MFAChallengeRepository
type InMemoryMFAChallengeRepository struct {
	mu   sync.RWMutex
	data map[string]*domain.MFAChallenge
}

// NewInMemoryMFAChallengeRepository creates a new in-memory MFA challenge repository
func NewInMemoryMFAChallengeRepository() *InMemoryMFAChallengeRepository {
	return &InMemoryMFAChallengeRepository{
		data: make(map[string]*domain.MFAChallenge),
	}
}

// Create creates a new MFA challenge
func (r *InMemoryMFAChallengeRepository) Create(ctx context.Context, challenge *domain.MFAChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	challenge.ID = uuid.New().String()
	challenge.CreatedAt = time.Now().UTC()

	r.data[challenge.ID] = challenge
	return nil
}

// FindByID finds an MFA challenge by ID
func (r *InMemoryMFAChallengeRepository) FindByID(ctx context.Context, id string) (*domain.MFAChallenge, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	challenge, exists := r.data[id]
	if !exists {
		return nil, domain.ErrNotFound
	}

	if challenge.ExpiresAt.Before(time.Now().UTC()) {
		return nil, domain.ErrNotFound
	}

	return challenge, nil
}

// FindByUserIDAndMethod finds an MFA challenge by user ID and method
func (r *InMemoryMFAChallengeRepository) FindByUserIDAndMethod(ctx context.Context, userID string, method domain.TwoFactorAuthMethod) (*domain.MFAChallenge, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var latest *domain.MFAChallenge
	now := time.Now().UTC()

	for _, challenge := range r.data {
		if challenge.UserID == userID && challenge.Method == method && challenge.ExpiresAt.After(now) {
			if latest == nil || challenge.CreatedAt.After(latest.CreatedAt) {
				latest = challenge
			}
		}
	}

	if latest == nil {
		return nil, domain.ErrNotFound
	}
	return latest, nil
}

// Update updates an existing MFA challenge
func (r *InMemoryMFAChallengeRepository) Update(ctx context.Context, challenge *domain.MFAChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.data[challenge.ID]; !exists {
		return domain.ErrNotFound
	}

	r.data[challenge.ID] = challenge
	return nil
}

// Delete deletes an MFA challenge
func (r *InMemoryMFAChallengeRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.data[id]; !exists {
		return domain.ErrNotFound
	}

	delete(r.data, id)
	return nil
}

// DeleteExpired deletes expired MFA challenges
func (r *InMemoryMFAChallengeRepository) DeleteExpired(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	for id, challenge := range r.data {
		if challenge.ExpiresAt.Before(now) {
			delete(r.data, id)
		}
	}
	return nil
}
