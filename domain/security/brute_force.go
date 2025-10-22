package security

import (
	"fmt"
	"time"
)

// BruteForceAttempt represents a failed login attempt
type BruteForceAttempt struct {
	ID        string
	Email     string
	IPAddress string
	Timestamp time.Time
}

// AccountLockout represents an account lockout due to too many failed attempts
type AccountLockout struct {
	ID        string
	Email     string
	LockedAt  time.Time
	UnlocksAt time.Time
}

// BruteForceRepository defines the interface for managing brute force attempts
type BruteForceRepository interface {
	// RecordAttempt records a failed login attempt for an email/IP combination
	RecordAttempt(email, ipAddress string) error

	// GetAttemptCount returns the number of failed attempts in the last duration for an email
	GetAttemptCount(email string, duration time.Duration) (int, error)

	// GetAttemptCountByIP returns the number of failed attempts in the last duration for an IP
	GetAttemptCountByIP(ipAddress string, duration time.Duration) (int, error)

	// LockAccount locks an account until the specified time
	LockAccount(email string, unlocksAt time.Time) error

	// UnlockAccount unlocks a locked account
	UnlockAccount(email string) error

	// IsAccountLocked checks if an account is currently locked
	IsAccountLocked(email string) (bool, error)

	// GetLockoutInfo returns lockout information for an email
	GetLockoutInfo(email string) (*AccountLockout, error)

	// ClearAttempts clears all failed attempts for an email
	ClearAttempts(email string) error
}

// BruteForceConfig contains configuration for brute force protection
type BruteForceConfig struct {
	// Enabled enables brute force protection
	Enabled bool

	// MaxAttempts is the maximum number of failed login attempts before lockout
	MaxAttempts int

	// LockoutDuration is how long an account is locked after exceeding max attempts
	LockoutDuration time.Duration

	// AttemptWindow is the time window in which attempts are counted
	AttemptWindow time.Duration

	// MaxAttemptsPerIP is the maximum number of failed attempts from a single IP address
	// Set to 0 to disable IP-based rate limiting
	MaxAttemptsPerIP int

	// IPAttemptWindow is the time window for IP-based attempt counting
	IPAttemptWindow time.Duration

	// UseSecondaryStorage enables using secondary storage (e.g., Redis) instead of in-memory
	UseSecondaryStorage bool
}

// Validate validates the brute force configuration
func (c *BruteForceConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.MaxAttempts <= 0 {
		return fmt.Errorf("max_attempts must be greater than 0")
	}

	if c.LockoutDuration <= 0 {
		return fmt.Errorf("lockout_duration must be greater than 0")
	}

	if c.AttemptWindow <= 0 {
		return fmt.Errorf("attempt_window must be greater than 0")
	}

	if c.MaxAttemptsPerIP > 0 && c.IPAttemptWindow <= 0 {
		return fmt.Errorf("ip_attempt_window must be greater than 0 when max_attempts_per_ip is set")
	}

	return nil
}

// DefaultBruteForceConfig returns the default brute force protection configuration
func DefaultBruteForceConfig() *BruteForceConfig {
	return &BruteForceConfig{
		Enabled:          true,
		MaxAttempts:      5,
		LockoutDuration:  15 * time.Minute,
		AttemptWindow:    15 * time.Minute,
		MaxAttemptsPerIP: 10,
		IPAttemptWindow:  15 * time.Minute,
	}
}
