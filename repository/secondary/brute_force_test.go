package secondary

import (
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBruteForceRepository_RecordAttempt(t *testing.T) {
	secondaryStorage := storage.NewInMemorySecondaryStorage()
	repo := NewSecondaryStorageBruteForceRepository(secondaryStorage)

	email := "test@example.com"
	ip := "192.168.1.1"

	// Record attempt
	err := repo.RecordAttempt(email, ip)
	require.NoError(t, err)

	// Check attempt count
	count, err := repo.GetAttemptCount(email, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Record another attempt
	err = repo.RecordAttempt(email, ip)
	require.NoError(t, err)

	count, err = repo.GetAttemptCount(email, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestBruteForceRepository_GetAttemptCountByIP(t *testing.T) {
	secondaryStorage := storage.NewInMemorySecondaryStorage()
	repo := NewSecondaryStorageBruteForceRepository(secondaryStorage)

	email := "test@example.com"
	ip := "192.168.1.1"

	// Record attempt
	err := repo.RecordAttempt(email, ip)
	require.NoError(t, err)

	// Check IP attempt count
	count, err := repo.GetAttemptCountByIP(ip, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestBruteForceRepository_AttemptExpiration(t *testing.T) {
	secondaryStorage := storage.NewInMemorySecondaryStorage()
	repo := NewSecondaryStorageBruteForceRepository(secondaryStorage)

	email := "test@example.com"
	ip := "192.168.1.1"

	// Record attempt
	err := repo.RecordAttempt(email, ip)
	require.NoError(t, err)

	// Check count with long window
	count, err := repo.GetAttemptCount(email, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Check count with short window (should be 0 since attempt is recent)
	count, err = repo.GetAttemptCount(email, time.Nanosecond)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestBruteForceRepository_LockAccount(t *testing.T) {
	secondaryStorage := storage.NewInMemorySecondaryStorage()
	repo := NewSecondaryStorageBruteForceRepository(secondaryStorage)

	email := "test@example.com"
	unlocksAt := time.Now().Add(time.Hour)

	// Lock account
	err := repo.LockAccount(email, unlocksAt)
	require.NoError(t, err)

	// Check if locked
	locked, err := repo.IsAccountLocked(email)
	require.NoError(t, err)
	assert.True(t, locked)

	// Get lockout info
	lockout, err := repo.GetLockoutInfo(email)
	require.NoError(t, err)
	require.NotNil(t, lockout)
	assert.Equal(t, email, lockout.Email)
	assert.True(t, lockout.UnlocksAt.After(time.Now()))
}

func TestBruteForceRepository_UnlockAccount(t *testing.T) {
	secondaryStorage := storage.NewInMemorySecondaryStorage()
	repo := NewSecondaryStorageBruteForceRepository(secondaryStorage)

	email := "test@example.com"
	unlocksAt := time.Now().Add(time.Hour)

	// Lock account
	err := repo.LockAccount(email, unlocksAt)
	require.NoError(t, err)

	// Verify locked
	locked, err := repo.IsAccountLocked(email)
	require.NoError(t, err)
	assert.True(t, locked)

	// Unlock account
	err = repo.UnlockAccount(email)
	require.NoError(t, err)

	// Verify unlocked
	locked, err = repo.IsAccountLocked(email)
	require.NoError(t, err)
	assert.False(t, locked)
}

func TestBruteForceRepository_ClearAttempts(t *testing.T) {
	secondaryStorage := storage.NewInMemorySecondaryStorage()
	repo := NewSecondaryStorageBruteForceRepository(secondaryStorage)

	email := "test@example.com"
	ip := "192.168.1.1"

	// Record attempts
	err := repo.RecordAttempt(email, ip)
	require.NoError(t, err)
	err = repo.RecordAttempt(email, ip)
	require.NoError(t, err)

	// Verify attempts recorded
	count, err := repo.GetAttemptCount(email, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Clear attempts
	err = repo.ClearAttempts(email)
	require.NoError(t, err)

	// Verify attempts cleared
	count, err = repo.GetAttemptCount(email, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestBruteForceRepository_ConcurrentAccess(t *testing.T) {
	secondaryStorage := storage.NewInMemorySecondaryStorage()
	repo := NewSecondaryStorageBruteForceRepository(secondaryStorage)

	email := "test@example.com"
	ip := "192.168.1.1"

	// Test concurrent recording
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			err := repo.RecordAttempt(email, ip)
			assert.NoError(t, err)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check final count
	count, err := repo.GetAttemptCount(email, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 10, count)
}
