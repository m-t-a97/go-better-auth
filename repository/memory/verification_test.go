package memory

import (
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerificationRepository(t *testing.T) {
	repo := NewVerificationRepository()
	assert.NotNil(t, repo)
}

func TestVerificationRepository_Create_Valid(t *testing.T) {
	repo := NewVerificationRepository()

	v := &verification.Verification{
		Identifier: "user@example.com",
		Token:      "verification-token-123",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := repo.Create(v)
	assert.NoError(t, err)
	assert.NotEmpty(t, v.ID)
	assert.False(t, v.CreatedAt.IsZero())
	assert.False(t, v.UpdatedAt.IsZero())
}

func TestVerificationRepository_Create_Nil(t *testing.T) {
	repo := NewVerificationRepository()

	err := repo.Create(nil)
	assert.Error(t, err)
}

func TestVerificationRepository_FindByToken_Exists(t *testing.T) {
	repo := NewVerificationRepository()

	v := &verification.Verification{
		Identifier: "user@example.com",
		Token:      "verification-token-123",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := repo.Create(v)
	require.NoError(t, err)

	found, err := repo.FindByToken(v.Token)
	assert.NoError(t, err)
	assert.Equal(t, v.ID, found.ID)
	assert.Equal(t, v.Token, found.Token)
}

func TestVerificationRepository_FindByToken_NotFound(t *testing.T) {
	repo := NewVerificationRepository()

	found, err := repo.FindByToken("non-existent-token")
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestVerificationRepository_FindByIdentifierAndType_Exists(t *testing.T) {
	repo := NewVerificationRepository()

	v := &verification.Verification{
		Identifier: "user@example.com",
		Token:      "verification-token-123",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := repo.Create(v)
	require.NoError(t, err)

	found, err := repo.FindByIdentifierAndType("user@example.com", verification.TypeEmailVerification)
	assert.NoError(t, err)
	assert.Equal(t, v.ID, found.ID)
}

func TestVerificationRepository_FindByIdentifierAndType_NotFound(t *testing.T) {
	repo := NewVerificationRepository()

	found, err := repo.FindByIdentifierAndType("user@example.com", verification.TypeEmailVerification)
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestVerificationRepository_Delete_Valid(t *testing.T) {
	repo := NewVerificationRepository()

	v := &verification.Verification{
		Identifier: "user@example.com",
		Token:      "verification-token-123",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := repo.Create(v)
	require.NoError(t, err)

	err = repo.Delete(v.ID)
	assert.NoError(t, err)

	found, err := repo.FindByToken(v.Token)
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestVerificationRepository_DeleteByToken_Valid(t *testing.T) {
	repo := NewVerificationRepository()

	v := &verification.Verification{
		Identifier: "user@example.com",
		Token:      "verification-token-123",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := repo.Create(v)
	require.NoError(t, err)

	err = repo.DeleteByToken(v.Token)
	assert.NoError(t, err)

	found, err := repo.FindByToken(v.Token)
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestVerificationRepository_DeleteByToken_NotFound(t *testing.T) {
	repo := NewVerificationRepository()

	err := repo.DeleteByToken("non-existent-token")
	assert.Error(t, err)
}

func TestVerificationRepository_DeleteExpired_Valid(t *testing.T) {
	repo := NewVerificationRepository()

	// Create expired verification
	expiredV := &verification.Verification{
		Identifier: "expired@example.com",
		Token:      "expired-token",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}
	err := repo.Create(expiredV)
	require.NoError(t, err)

	// Create valid verification
	validV := &verification.Verification{
		Identifier: "valid@example.com",
		Token:      "valid-token",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
	err = repo.Create(validV)
	require.NoError(t, err)

	err = repo.DeleteExpired()
	assert.NoError(t, err)

	// Expired should be gone
	found, err := repo.FindByToken(expiredV.Token)
	assert.Error(t, err)
	assert.Nil(t, found)

	// Valid should remain
	found, err = repo.FindByToken(validV.Token)
	assert.NoError(t, err)
	assert.NotNil(t, found)
}

func TestVerificationRepository_Count(t *testing.T) {
	repo := NewVerificationRepository()

	count, err := repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	v := &verification.Verification{
		Identifier: "user@example.com",
		Token:      "verification-token-123",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err = repo.Create(v)
	require.NoError(t, err)

	count, err = repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestVerificationRepository_ExistsByToken(t *testing.T) {
	repo := NewVerificationRepository()

	v := &verification.Verification{
		Identifier: "user@example.com",
		Token:      "verification-token-123",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := repo.Create(v)
	require.NoError(t, err)

	exists, err := repo.ExistsByToken(v.Token)
	assert.NoError(t, err)
	assert.True(t, exists)

	exists, err = repo.ExistsByToken("non-existent-token")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestVerificationRepository_ExistsByIdentifierAndType(t *testing.T) {
	repo := NewVerificationRepository()

	v := &verification.Verification{
		Identifier: "user@example.com",
		Token:      "verification-token-123",
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := repo.Create(v)
	require.NoError(t, err)

	exists, err := repo.ExistsByIdentifierAndType("user@example.com", verification.TypeEmailVerification)
	assert.NoError(t, err)
	assert.True(t, exists)

	exists, err = repo.ExistsByIdentifierAndType("user@example.com", verification.TypePasswordReset)
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestVerification_IsExpired_False(t *testing.T) {
	v := &verification.Verification{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	assert.False(t, v.IsExpired())
}

func TestVerification_IsExpired_True(t *testing.T) {
	v := &verification.Verification{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	assert.True(t, v.IsExpired())
}
