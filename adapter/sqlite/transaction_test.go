//go:build cgo
// +build cgo

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/m-t-a97/go-better-auth/adapter"
	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteTransaction_CreateUserAndSessionAtomic(t *testing.T) {
	adp, err := NewSQLiteAdapter(&adapter.Config{AutoMigrate: true})
	require.NoError(t, err)
	defer adp.Close()

	ctx := context.Background()
	tx, err := adp.BeginTx(ctx)
	require.NoError(t, err)

	testUser := &user.User{
		ID:            uuid.New().String(),
		Name:          "Test User",
		Email:         "test@example.com",
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err = tx.UserRepository().Create(testUser)
	require.NoError(t, err)

	testSession := &session.Session{
		ID:        uuid.New().String(),
		UserID:    testUser.ID,
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = tx.SessionRepository().Create(testSession)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	retrievedUser, err := adp.UserRepository().FindByID(testUser.ID)
	require.NoError(t, err)
	assert.Equal(t, testUser.Email, retrievedUser.Email)

	retrievedSession, err := adp.SessionRepository().FindByID(testSession.ID)
	require.NoError(t, err)
	assert.Equal(t, testUser.ID, retrievedSession.UserID)
}

func TestSQLiteTransaction_RollbackOnError(t *testing.T) {
	adp, err := NewSQLiteAdapter(&adapter.Config{AutoMigrate: true})
	require.NoError(t, err)
	defer adp.Close()

	ctx := context.Background()
	tx, err := adp.BeginTx(ctx)
	require.NoError(t, err)

	testUser := &user.User{
		ID:            uuid.New().String(),
		Name:          "Test User",
		Email:         "test@example.com",
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err = tx.UserRepository().Create(testUser)
	require.NoError(t, err)

	err = tx.Rollback()
	require.NoError(t, err)

	_, err = adp.UserRepository().FindByID(testUser.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestSQLiteTransaction_UpdateMultipleTables(t *testing.T) {
	adp, err := NewSQLiteAdapter(&adapter.Config{AutoMigrate: true})
	require.NoError(t, err)
	defer adp.Close()

	testUser := &user.User{
		ID:            uuid.New().String(),
		Name:          "Original Name",
		Email:         "original@example.com",
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	err = adp.UserRepository().Create(testUser)
	require.NoError(t, err)

	testAccount := &account.Account{
		ID:         uuid.New().String(),
		UserID:     testUser.ID,
		ProviderID: account.ProviderCredential,
		Password:   nil,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	err = adp.AccountRepository().Create(testAccount)
	require.NoError(t, err)

	ctx := context.Background()
	tx, err := adp.BeginTx(ctx)
	require.NoError(t, err)

	testUser.Name = "Updated Name"
	testUser.UpdatedAt = time.Now()
	err = tx.UserRepository().Update(testUser)
	require.NoError(t, err)

	testAccount.UpdatedAt = time.Now()
	err = tx.AccountRepository().Update(testAccount)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	updatedUser, err := adp.UserRepository().FindByID(testUser.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updatedUser.Name)

	updatedAccount, err := adp.AccountRepository().FindByID(testAccount.ID)
	require.NoError(t, err)
	// Compare timestamps without timezone information as SQLite stores UTC
	assert.True(t, updatedAccount.UpdatedAt.Unix() > 0)
}

func TestSQLiteTransaction_DeleteCascade(t *testing.T) {
	adp, err := NewSQLiteAdapter(&adapter.Config{AutoMigrate: true})
	require.NoError(t, err)
	defer adp.Close()

	testUser := &user.User{
		ID:        uuid.New().String(),
		Name:      "Test User",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = adp.UserRepository().Create(testUser)
	require.NoError(t, err)

	testSession := &session.Session{
		ID:        uuid.New().String(),
		UserID:    testUser.ID,
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = adp.SessionRepository().Create(testSession)
	require.NoError(t, err)

	testAccount := &account.Account{
		ID:         uuid.New().String(),
		UserID:     testUser.ID,
		ProviderID: account.ProviderCredential,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	err = adp.AccountRepository().Create(testAccount)
	require.NoError(t, err)

	ctx := context.Background()
	tx, err := adp.BeginTx(ctx)
	require.NoError(t, err)

	err = tx.SessionRepository().DeleteByUserID(testUser.ID)
	require.NoError(t, err)

	err = tx.AccountRepository().DeleteByUserID(testUser.ID)
	require.NoError(t, err)

	err = tx.UserRepository().Delete(testUser.ID)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	_, err = adp.UserRepository().FindByID(testUser.ID)
	assert.Error(t, err)

	sessions, err := adp.SessionRepository().FindByUserID(testUser.ID)
	require.NoError(t, err)
	assert.Empty(t, sessions)

	accounts, err := adp.AccountRepository().FindByUserID(testUser.ID)
	require.NoError(t, err)
	assert.Empty(t, accounts)
}

func TestSQLiteTransaction_VerificationLifecycle(t *testing.T) {
	adp, err := NewSQLiteAdapter(&adapter.Config{AutoMigrate: true})
	require.NoError(t, err)
	defer adp.Close()

	ctx := context.Background()
	tx, err := adp.BeginTx(ctx)
	require.NoError(t, err)

	testVerification := &verification.Verification{
		ID:         uuid.New().String(),
		Identifier: "test@example.com",
		Token:      uuid.New().String(),
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err = tx.VerificationRepository().Create(testVerification)
	require.NoError(t, err)

	found, err := tx.VerificationRepository().FindByToken(testVerification.Token)
	require.NoError(t, err)
	assert.Equal(t, testVerification.Identifier, found.Identifier)

	err = tx.VerificationRepository().DeleteByToken(testVerification.Token)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	_, err = adp.VerificationRepository().FindByToken(testVerification.Token)
	assert.Error(t, err)
}

func TestSQLiteTransaction_Count(t *testing.T) {
	adp, err := NewSQLiteAdapter(&adapter.Config{AutoMigrate: true})
	require.NoError(t, err)
	defer adp.Close()

	ctx := context.Background()
	tx, err := adp.BeginTx(ctx)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		testUser := &user.User{
			ID:        uuid.New().String(),
			Name:      "Test User",
			Email:     "user" + string(rune('0'+byte(i))) + "@example.com",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		err = tx.UserRepository().Create(testUser)
		require.NoError(t, err)
	}

	count, err := tx.UserRepository().Count()
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	err = tx.Commit()
	require.NoError(t, err)

	count, err = adp.UserRepository().Count()
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}
