//go:build cgo
// +build cgo

package sqlite

import (
	"os"
	"testing"

	"github.com/m-t-a97/go-better-auth/adapter"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSQLiteAdapter(t *testing.T) {
	// Use in-memory database for testing
	cfg := &adapter.Config{
		DSN:         "file::memory:?cache=shared",
		AutoMigrate: true,
	}

	a, err := NewSQLiteAdapter(cfg)
	require.NoError(t, err)
	require.NotNil(t, a)

	defer a.Close()
}

func TestSQLiteAdapter_UserRepository(t *testing.T) {
	cfg := &adapter.Config{
		DSN:         "file::memory:?cache=shared",
		AutoMigrate: true,
	}

	a, err := NewSQLiteAdapter(cfg)
	require.NoError(t, err)
	defer a.Close()

	// Test user creation through repository
	userRepo := a.UserRepository()
	assert.NotNil(t, userRepo)

	u := &user.User{
		ID:    "user-1",
		Name:  "Test User",
		Email: "test@example.com",
	}

	// Create user
	err = userRepo.Create(u)
	assert.NoError(t, err)

	// Find user
	found, err := userRepo.FindByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.Email, found.Email)
	assert.Equal(t, u.Name, found.Name)
}

func TestSQLiteAdapter_FileDatabase(t *testing.T) {
	// Create temporary file for database
	tmpFile, err := os.CreateTemp("", "test-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cfg := &adapter.Config{
		DSN:         tmpFile.Name(),
		AutoMigrate: true,
	}

	a, err := NewSQLiteAdapter(cfg)
	require.NoError(t, err)
	defer a.Close()

	userRepo := a.UserRepository()

	u := &user.User{
		ID:    "user-1",
		Name:  "Persistent User",
		Email: "persistent@example.com",
	}

	err = userRepo.Create(u)
	assert.NoError(t, err)

	count, err := userRepo.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}
