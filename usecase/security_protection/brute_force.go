package security_protection

import (
	"fmt"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/security"
)

// BruteForceService provides operations for brute force protection
type BruteForceService struct {
	repo   security.BruteForceRepository
	config *security.BruteForceConfig
}

// NewBruteForceService creates a new brute force service
func NewBruteForceService(repo security.BruteForceRepository, config *security.BruteForceConfig) *BruteForceService {
	if config == nil {
		config = security.DefaultBruteForceConfig()
	}
	return &BruteForceService{
		repo:   repo,
		config: config,
	}
}

// CheckLoginAttempt checks if a login can be attempted for the given email
// Returns an error if the account is locked
func (s *BruteForceService) CheckLoginAttempt(email, ipAddress string) error {
	if !s.config.Enabled {
		return nil
	}

	// Check if account is locked
	locked, err := s.repo.IsAccountLocked(email)
	if err != nil {
		return fmt.Errorf("failed to check account lock status: %w", err)
	}

	if locked {
		return fmt.Errorf("account is temporarily locked")
	}

	// Check IP-based rate limiting if enabled
	if s.config.MaxAttemptsPerIP > 0 {
		count, err := s.repo.GetAttemptCountByIP(ipAddress, s.config.IPAttemptWindow)
		if err != nil {
			return fmt.Errorf("failed to check IP attempt count: %w", err)
		}

		if count >= s.config.MaxAttemptsPerIP {
			return fmt.Errorf("too many login attempts from this IP address")
		}
	}

	return nil
}

// RecordFailedAttempt records a failed login attempt and locks the account if threshold is exceeded
func (s *BruteForceService) RecordFailedAttempt(email, ipAddress string) error {
	if !s.config.Enabled {
		return nil
	}

	// Record the attempt
	if err := s.repo.RecordAttempt(email, ipAddress); err != nil {
		return fmt.Errorf("failed to record attempt: %w", err)
	}

	// Check attempt count
	count, err := s.repo.GetAttemptCount(email, s.config.AttemptWindow)
	if err != nil {
		return fmt.Errorf("failed to get attempt count: %w", err)
	}

	// Lock account if threshold exceeded
	if count >= s.config.MaxAttempts {
		unlocksAt := time.Now().Add(s.config.LockoutDuration)
		if err := s.repo.LockAccount(email, unlocksAt); err != nil {
			return fmt.Errorf("failed to lock account: %w", err)
		}
	}

	return nil
}

// ClearAttempts clears all failed attempts for an email and unlocks the account
func (s *BruteForceService) ClearAttempts(email string) error {
	if !s.config.Enabled {
		return nil
	}

	// Clear attempts
	if err := s.repo.ClearAttempts(email); err != nil {
		return fmt.Errorf("failed to clear attempts: %w", err)
	}

	// Unlock account
	if err := s.repo.UnlockAccount(email); err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	return nil
}

// GetLockoutInfo gets lockout information for an account
func (s *BruteForceService) GetLockoutInfo(email string) (*security.AccountLockout, error) {
	if !s.config.Enabled {
		return nil, nil
	}

	return s.repo.GetLockoutInfo(email)
}
