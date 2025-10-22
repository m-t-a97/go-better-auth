package security_protection

import (
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/security"
	"github.com/m-t-a97/go-better-auth/repository/memory"
)

func TestBruteForceService_CheckLoginAttempt_Success(t *testing.T) {
	repo := memory.NewInMemoryBruteForceRepository()
	config := &security.BruteForceConfig{
		Enabled:          true,
		MaxAttempts:      5,
		LockoutDuration:  15 * time.Minute,
		AttemptWindow:    15 * time.Minute,
		MaxAttemptsPerIP: 10,
		IPAttemptWindow:  15 * time.Minute,
	}
	svc := NewBruteForceService(repo, config)

	// Should allow login when no attempts have been made
	err := svc.CheckLoginAttempt("test@example.com", "192.168.1.1")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestBruteForceService_CheckLoginAttempt_AccountLocked(t *testing.T) {
	repo := memory.NewInMemoryBruteForceRepository()
	config := &security.BruteForceConfig{
		Enabled:          true,
		MaxAttempts:      5,
		LockoutDuration:  15 * time.Minute,
		AttemptWindow:    15 * time.Minute,
		MaxAttemptsPerIP: 10,
		IPAttemptWindow:  15 * time.Minute,
	}
	svc := NewBruteForceService(repo, config)
	email := "test@example.com"

	// Lock the account
	unlockTime := time.Now().Add(15 * time.Minute)
	if err := repo.LockAccount(email, unlockTime); err != nil {
		t.Fatalf("LockAccount failed: %v", err)
	}

	// Should reject login when account is locked
	err := svc.CheckLoginAttempt(email, "192.168.1.1")
	if err == nil {
		t.Error("expected error for locked account")
	}
}

func TestBruteForceService_CheckLoginAttempt_IPRateLimit(t *testing.T) {
	repo := memory.NewInMemoryBruteForceRepository()
	config := &security.BruteForceConfig{
		Enabled:          true,
		MaxAttempts:      5,
		LockoutDuration:  15 * time.Minute,
		AttemptWindow:    15 * time.Minute,
		MaxAttemptsPerIP: 3,
		IPAttemptWindow:  15 * time.Minute,
	}
	svc := NewBruteForceService(repo, config)
	ip := "192.168.1.1"

	// Record attempts from the same IP
	for i := 0; i < 3; i++ {
		if err := repo.RecordAttempt("user"+string(rune(i))+"@example.com", ip); err != nil {
			t.Fatalf("RecordAttempt failed: %v", err)
		}
	}

	// Should reject login due to IP rate limit
	err := svc.CheckLoginAttempt("newuser@example.com", ip)
	if err == nil {
		t.Error("expected error for IP rate limit exceeded")
	}
}

func TestBruteForceService_RecordFailedAttempt_NoLockout(t *testing.T) {
	repo := memory.NewInMemoryBruteForceRepository()
	config := &security.BruteForceConfig{
		Enabled:          true,
		MaxAttempts:      5,
		LockoutDuration:  15 * time.Minute,
		AttemptWindow:    15 * time.Minute,
		MaxAttemptsPerIP: 10,
		IPAttemptWindow:  15 * time.Minute,
	}
	svc := NewBruteForceService(repo, config)
	email := "test@example.com"

	// Record 3 failed attempts (below threshold of 5)
	for i := 0; i < 3; i++ {
		if err := svc.RecordFailedAttempt(email, "192.168.1.1"); err != nil {
			t.Fatalf("RecordFailedAttempt failed: %v", err)
		}
	}

	// Account should not be locked
	locked, err := repo.IsAccountLocked(email)
	if err != nil {
		t.Fatalf("IsAccountLocked failed: %v", err)
	}

	if locked {
		t.Error("expected account to not be locked")
	}
}

func TestBruteForceService_RecordFailedAttempt_WithLockout(t *testing.T) {
	repo := memory.NewInMemoryBruteForceRepository()
	config := &security.BruteForceConfig{
		Enabled:          true,
		MaxAttempts:      5,
		LockoutDuration:  15 * time.Minute,
		AttemptWindow:    15 * time.Minute,
		MaxAttemptsPerIP: 10,
		IPAttemptWindow:  15 * time.Minute,
	}
	svc := NewBruteForceService(repo, config)
	email := "test@example.com"

	// Record 5 failed attempts to trigger lockout
	for i := 0; i < 5; i++ {
		if err := svc.RecordFailedAttempt(email, "192.168.1.1"); err != nil {
			t.Fatalf("RecordFailedAttempt failed: %v", err)
		}
	}

	// Account should be locked
	locked, err := repo.IsAccountLocked(email)
	if err != nil {
		t.Fatalf("IsAccountLocked failed: %v", err)
	}

	if !locked {
		t.Error("expected account to be locked")
	}
}

func TestBruteForceService_ClearAttempts(t *testing.T) {
	repo := memory.NewInMemoryBruteForceRepository()
	config := &security.BruteForceConfig{
		Enabled:          true,
		MaxAttempts:      5,
		LockoutDuration:  15 * time.Minute,
		AttemptWindow:    15 * time.Minute,
		MaxAttemptsPerIP: 10,
		IPAttemptWindow:  15 * time.Minute,
	}
	svc := NewBruteForceService(repo, config)
	email := "test@example.com"

	// Record and lock
	for i := 0; i < 5; i++ {
		if err := svc.RecordFailedAttempt(email, "192.168.1.1"); err != nil {
			t.Fatalf("RecordFailedAttempt failed: %v", err)
		}
	}

	// Clear attempts
	if err := svc.ClearAttempts(email); err != nil {
		t.Fatalf("ClearAttempts failed: %v", err)
	}

	// Account should be unlocked
	locked, err := repo.IsAccountLocked(email)
	if err != nil {
		t.Fatalf("IsAccountLocked failed: %v", err)
	}

	if locked {
		t.Error("expected account to be unlocked after clearing")
	}

	// Attempts should be cleared
	count, err := repo.GetAttemptCount(email, 15*time.Minute)
	if err != nil {
		t.Fatalf("GetAttemptCount failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 attempts after clearing, got %d", count)
	}
}

func TestBruteForceService_DisabledConfig(t *testing.T) {
	repo := memory.NewInMemoryBruteForceRepository()
	config := &security.BruteForceConfig{
		Enabled: false,
	}
	svc := NewBruteForceService(repo, config)

	// Should allow login when brute force protection is disabled
	err := svc.CheckLoginAttempt("test@example.com", "192.168.1.1")
	if err != nil {
		t.Errorf("expected no error when disabled, got %v", err)
	}

	// Should not record attempts when disabled
	err = svc.RecordFailedAttempt("test@example.com", "192.168.1.1")
	if err != nil {
		t.Errorf("expected no error when disabled, got %v", err)
	}
}
