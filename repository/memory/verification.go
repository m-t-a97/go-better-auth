package memory

import (
	"fmt"
	"sync"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
	"github.com/google/uuid"
)

// VerificationRepository implements an in-memory verification repository
type VerificationRepository struct {
	mu            sync.RWMutex
	verifications map[string]*verification.Verification
}

// NewVerificationRepository creates a new in-memory verification repository
func NewVerificationRepository() *VerificationRepository {
	return &VerificationRepository{
		verifications: make(map[string]*verification.Verification),
	}
}

// Create creates a new verification token
func (r *VerificationRepository) Create(v *verification.Verification) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if v == nil {
		return fmt.Errorf("verification cannot be nil")
	}

	// Generate ID if not set
	if v.ID == "" {
		v.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	v.CreatedAt = now
	v.UpdatedAt = now

	r.verifications[v.ID] = v
	return nil
}

// FindByToken retrieves a verification by token
func (r *VerificationRepository) FindByToken(token string) (*verification.Verification, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, v := range r.verifications {
		if v.Token == token {
			return v, nil
		}
	}

	return nil, fmt.Errorf("verification not found")
}

// FindByHashedToken retrieves a verification by matching a plain token against a hashed token
func (r *VerificationRepository) FindByHashedToken(plainToken string) (*verification.Verification, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, v := range r.verifications {
		if crypto.VerifyVerificationToken(plainToken, v.Token) {
			return v, nil
		}
	}

	return nil, fmt.Errorf("verification not found")
}

// FindByIdentifierAndType retrieves a verification by identifier and type
func (r *VerificationRepository) FindByIdentifierAndType(identifier string, verType verification.VerificationType) (*verification.Verification, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, v := range r.verifications {
		if v.Identifier == identifier && v.Type == verType {
			return v, nil
		}
	}

	return nil, fmt.Errorf("verification not found")
}

// Delete deletes a verification by ID
func (r *VerificationRepository) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.verifications[id]; !ok {
		return fmt.Errorf("verification not found")
	}

	delete(r.verifications, id)
	return nil
}

// DeleteByToken deletes a verification by token
func (r *VerificationRepository) DeleteByToken(token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, v := range r.verifications {
		if v.Token == token {
			delete(r.verifications, id)
			return nil
		}
	}

	return fmt.Errorf("verification not found")
}

// DeleteExpired deletes all expired verifications
func (r *VerificationRepository) DeleteExpired() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for id, v := range r.verifications {
		if v.ExpiresAt.Before(now) {
			delete(r.verifications, id)
		}
	}

	return nil
}

// Count returns the total number of verifications
func (r *VerificationRepository) Count() (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.verifications), nil
}

// ExistsByToken checks if a verification exists by token
func (r *VerificationRepository) ExistsByToken(token string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, v := range r.verifications {
		if v.Token == token {
			return true, nil
		}
	}

	return false, nil
}

// ExistsByIdentifierAndType checks if a verification exists by identifier and type
func (r *VerificationRepository) ExistsByIdentifierAndType(identifier string, verType verification.VerificationType) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, v := range r.verifications {
		if v.Identifier == identifier && v.Type == verType {
			return true, nil
		}
	}

	return false, nil
}
