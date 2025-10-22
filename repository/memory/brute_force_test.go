package memory

import (
	"testing"
	"time"
)

func TestBruteForceRepository_RecordAndGetAttempts(t *testing.T) {
	repo := NewInMemoryBruteForceRepository()
	email := "test@example.com"
	ip := "192.168.1.1"

	// Record some attempts
	for i := 0; i < 3; i++ {
		if err := repo.RecordAttempt(email, ip); err != nil {
			t.Fatalf("RecordAttempt failed: %v", err)
		}
	}

	// Check attempt count
	count, err := repo.GetAttemptCount(email, 15*time.Minute)
	if err != nil {
		t.Fatalf("GetAttemptCount failed: %v", err)
	}

	if count != 3 {
		t.Errorf("expected 3 attempts, got %d", count)
	}
}

func TestBruteForceRepository_AttemptExpiry(t *testing.T) {
	repo := NewInMemoryBruteForceRepository()
	email := "test@example.com"

	// Record an attempt
	if err := repo.RecordAttempt(email, "192.168.1.1"); err != nil {
		t.Fatalf("RecordAttempt failed: %v", err)
	}

	// Check with a very short duration - should not count
	count, err := repo.GetAttemptCount(email, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("GetAttemptCount failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 attempts within 1ns window, got %d", count)
	}

	// Check with a long duration - should count
	count, err = repo.GetAttemptCount(email, 1*time.Hour)
	if err != nil {
		t.Fatalf("GetAttemptCount failed: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 attempt within 1 hour window, got %d", count)
	}
}

func TestBruteForceRepository_IPAttempts(t *testing.T) {
	repo := NewInMemoryBruteForceRepository()

	// Record attempts from different IPs
	emails := []string{"user1@example.com", "user2@example.com", "user3@example.com"}
	ip := "192.168.1.1"

	for _, email := range emails {
		if err := repo.RecordAttempt(email, ip); err != nil {
			t.Fatalf("RecordAttempt failed: %v", err)
		}
	}

	// Check IP attempt count
	count, err := repo.GetAttemptCountByIP(ip, 15*time.Minute)
	if err != nil {
		t.Fatalf("GetAttemptCountByIP failed: %v", err)
	}

	if count != 3 {
		t.Errorf("expected 3 attempts from IP, got %d", count)
	}
}

func TestBruteForceRepository_LockAndUnlock(t *testing.T) {
	repo := NewInMemoryBruteForceRepository()
	email := "test@example.com"
	unlockTime := time.Now().Add(15 * time.Minute)

	// Lock the account
	if err := repo.LockAccount(email, unlockTime); err != nil {
		t.Fatalf("LockAccount failed: %v", err)
	}

	// Check if locked
	locked, err := repo.IsAccountLocked(email)
	if err != nil {
		t.Fatalf("IsAccountLocked failed: %v", err)
	}

	if !locked {
		t.Error("expected account to be locked")
	}

	// Get lockout info
	lockout, err := repo.GetLockoutInfo(email)
	if err != nil {
		t.Fatalf("GetLockoutInfo failed: %v", err)
	}

	if lockout == nil {
		t.Error("expected lockout info, got nil")
	}

	if lockout.Email != email {
		t.Errorf("expected email %s, got %s", email, lockout.Email)
	}

	// Unlock
	if err := repo.UnlockAccount(email); err != nil {
		t.Fatalf("UnlockAccount failed: %v", err)
	}

	// Check if unlocked
	locked, err = repo.IsAccountLocked(email)
	if err != nil {
		t.Fatalf("IsAccountLocked failed: %v", err)
	}

	if locked {
		t.Error("expected account to be unlocked")
	}
}

func TestBruteForceRepository_ClearAttempts(t *testing.T) {
	repo := NewInMemoryBruteForceRepository()
	email := "test@example.com"

	// Record attempts
	for i := 0; i < 5; i++ {
		if err := repo.RecordAttempt(email, "192.168.1.1"); err != nil {
			t.Fatalf("RecordAttempt failed: %v", err)
		}
	}

	// Clear attempts
	if err := repo.ClearAttempts(email); err != nil {
		t.Fatalf("ClearAttempts failed: %v", err)
	}

	// Check that attempts are cleared
	count, err := repo.GetAttemptCount(email, 15*time.Minute)
	if err != nil {
		t.Fatalf("GetAttemptCount failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 attempts after clearing, got %d", count)
	}
}

func TestBruteForceRepository_LockoutExpiry(t *testing.T) {
	repo := NewInMemoryBruteForceRepository()
	email := "test@example.com"

	// Lock with immediate expiry
	unlockTime := time.Now().Add(-1 * time.Second)
	if err := repo.LockAccount(email, unlockTime); err != nil {
		t.Fatalf("LockAccount failed: %v", err)
	}

	// Check if locked - should return false since it's already expired
	locked, err := repo.IsAccountLocked(email)
	if err != nil {
		t.Fatalf("IsAccountLocked failed: %v", err)
	}

	if locked {
		t.Error("expected account to be unlocked (lockout expired)")
	}

	// GetLockoutInfo should also return nil for expired lockouts
	lockout, err := repo.GetLockoutInfo(email)
	if err != nil {
		t.Fatalf("GetLockoutInfo failed: %v", err)
	}

	if lockout != nil {
		t.Error("expected nil lockout info for expired lockout")
	}
}
