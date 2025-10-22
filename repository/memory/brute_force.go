package memory

import (
	"sync"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/security"
)

// InMemoryBruteForceRepository is an in-memory implementation of security.InMemoryBruteForceRepository
type InMemoryBruteForceRepository struct {
	mu       sync.RWMutex
	attempts map[string][]*security.BruteForceAttempt // key: email
	lockouts map[string]*security.AccountLockout      // key: email
}

// NewInMemoryBruteForceRepository creates a new in-memory brute force repository
func NewInMemoryBruteForceRepository() *InMemoryBruteForceRepository {
	return &InMemoryBruteForceRepository{
		attempts: make(map[string][]*security.BruteForceAttempt),
		lockouts: make(map[string]*security.AccountLockout),
	}
}

// RecordAttempt records a failed login attempt for an email
func (r *InMemoryBruteForceRepository) RecordAttempt(email, ipAddress string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	attempt := &security.BruteForceAttempt{
		Email:     email,
		IPAddress: ipAddress,
		Timestamp: time.Now(),
	}

	r.attempts[email] = append(r.attempts[email], attempt)
	return nil
}

// GetAttemptCount returns the number of failed attempts in the last duration for an email
func (r *InMemoryBruteForceRepository) GetAttemptCount(email string, duration time.Duration) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	attempts := r.attempts[email]
	if len(attempts) == 0 {
		return 0, nil
	}

	cutoffTime := time.Now().Add(-duration)
	count := 0
	for _, attempt := range attempts {
		if attempt.Timestamp.After(cutoffTime) {
			count++
		}
	}

	return count, nil
}

// GetAttemptCountByIP returns the number of failed attempts in the last duration for an IP
func (r *InMemoryBruteForceRepository) GetAttemptCountByIP(ipAddress string, duration time.Duration) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cutoffTime := time.Now().Add(-duration)
	count := 0

	// Search through all attempts for matching IP
	for _, attempts := range r.attempts {
		for _, attempt := range attempts {
			if attempt.IPAddress == ipAddress && attempt.Timestamp.After(cutoffTime) {
				count++
			}
		}
	}

	return count, nil
}

// LockAccount locks an account until the specified time
func (r *InMemoryBruteForceRepository) LockAccount(email string, unlocksAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lockouts[email] = &security.AccountLockout{
		Email:     email,
		LockedAt:  time.Now(),
		UnlocksAt: unlocksAt,
	}

	return nil
}

// UnlockAccount unlocks a locked account
func (r *InMemoryBruteForceRepository) UnlockAccount(email string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.lockouts, email)
	return nil
}

// IsAccountLocked checks if an account is currently locked
func (r *InMemoryBruteForceRepository) IsAccountLocked(email string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lockout, exists := r.lockouts[email]
	if !exists {
		return false, nil
	}

	// Check if lockout has expired
	if time.Now().After(lockout.UnlocksAt) {
		return false, nil
	}

	return true, nil
}

// GetLockoutInfo returns lockout information for an email
func (r *InMemoryBruteForceRepository) GetLockoutInfo(email string) (*security.AccountLockout, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lockout, exists := r.lockouts[email]
	if !exists {
		return nil, nil
	}

	// Check if lockout has expired
	if time.Now().After(lockout.UnlocksAt) {
		return nil, nil
	}

	return lockout, nil
}

// ClearAttempts clears all failed attempts for an email
func (r *InMemoryBruteForceRepository) ClearAttempts(email string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.attempts, email)
	return nil
}
