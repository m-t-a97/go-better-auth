package memory

import (
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionRepository(t *testing.T) {
	repo := NewSessionRepository()
	assert.NotNil(t, repo)
}

func TestSessionRepository_Create_Valid(t *testing.T) {
	repo := NewSessionRepository()

	s := &session.Session{
		UserID:    "user-123",
		Token:     "session-token-12345678",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(s)
	assert.NoError(t, err)
	assert.NotEmpty(t, s.ID)
	assert.False(t, s.CreatedAt.IsZero())
	assert.False(t, s.UpdatedAt.IsZero())
}

func TestSessionRepository_Create_Nil(t *testing.T) {
	repo := NewSessionRepository()

	err := repo.Create(nil)
	assert.Error(t, err)
}

func TestSessionRepository_FindByID_Exists(t *testing.T) {
	repo := NewSessionRepository()

	s := &session.Session{
		UserID:    "user-123",
		Token:     "session-token-12345678",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(s)
	require.NoError(t, err)

	found, err := repo.FindByID(s.ID)
	assert.NoError(t, err)
	assert.Equal(t, s.ID, found.ID)
	assert.Equal(t, s.UserID, found.UserID)
	assert.Equal(t, s.Token, found.Token)
}

func TestSessionRepository_FindByID_NotFound(t *testing.T) {
	repo := NewSessionRepository()

	found, err := repo.FindByID("non-existent-id")
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestSessionRepository_FindByToken_Exists(t *testing.T) {
	repo := NewSessionRepository()

	s := &session.Session{
		UserID:    "user-123",
		Token:     "session-token-12345678",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(s)
	require.NoError(t, err)

	found, err := repo.FindByToken(s.Token)
	assert.NoError(t, err)
	assert.Equal(t, s.ID, found.ID)
	assert.Equal(t, s.Token, found.Token)
}

func TestSessionRepository_FindByToken_NotFound(t *testing.T) {
	repo := NewSessionRepository()

	found, err := repo.FindByToken("non-existent-token")
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestSessionRepository_FindByUserID_Exists(t *testing.T) {
	repo := NewSessionRepository()

	userID := "user-123"
	for i := 0; i < 3; i++ {
		s := &session.Session{
			UserID:    userID,
			Token:     "token-" + string(rune('0'+i)),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := repo.Create(s)
		require.NoError(t, err)
	}

	sessions, err := repo.FindByUserID(userID)
	assert.NoError(t, err)
	assert.Len(t, sessions, 3)

	for _, s := range sessions {
		assert.Equal(t, userID, s.UserID)
	}
}

func TestSessionRepository_FindByUserID_NotFound(t *testing.T) {
	repo := NewSessionRepository()

	sessions, err := repo.FindByUserID("non-existent-user")
	assert.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestSessionRepository_Update_Valid(t *testing.T) {
	repo := NewSessionRepository()

	s := &session.Session{
		UserID:    "user-123",
		Token:     "session-token-12345678",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(s)
	require.NoError(t, err)

	updatedToken := "updated-token"
	s.Token = updatedToken
	err = repo.Update(s)
	assert.NoError(t, err)

	found, err := repo.FindByID(s.ID)
	require.NoError(t, err)
	assert.Equal(t, updatedToken, found.Token)
}

func TestSessionRepository_Update_NotFound(t *testing.T) {
	repo := NewSessionRepository()

	s := &session.Session{
		ID:        "non-existent-id",
		UserID:    "user-123",
		Token:     "session-token-12345678",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Update(s)
	assert.Error(t, err)
}

func TestSessionRepository_Update_Nil(t *testing.T) {
	repo := NewSessionRepository()

	err := repo.Update(nil)
	assert.Error(t, err)
}

func TestSessionRepository_Delete_Valid(t *testing.T) {
	repo := NewSessionRepository()

	s := &session.Session{
		UserID:    "user-123",
		Token:     "session-token-12345678",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(s)
	require.NoError(t, err)

	err = repo.Delete(s.ID)
	assert.NoError(t, err)

	found, err := repo.FindByID(s.ID)
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestSessionRepository_Delete_NotFound(t *testing.T) {
	repo := NewSessionRepository()

	err := repo.Delete("non-existent-id")
	assert.Error(t, err)
}

func TestSessionRepository_DeleteByUserID_Valid(t *testing.T) {
	repo := NewSessionRepository()

	userID := "user-123"
	sessionIDs := []string{}
	for i := 0; i < 3; i++ {
		s := &session.Session{
			UserID:    userID,
			Token:     "token-" + string(rune('0'+i)),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := repo.Create(s)
		require.NoError(t, err)
		sessionIDs = append(sessionIDs, s.ID)
	}

	err := repo.DeleteByUserID(userID)
	assert.NoError(t, err)

	sessions, err := repo.FindByUserID(userID)
	assert.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestSessionRepository_DeleteExpired_Valid(t *testing.T) {
	repo := NewSessionRepository()

	// Create expired session
	s1 := &session.Session{
		UserID:    "user-123",
		Token:     "expired-token",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	err := repo.Create(s1)
	require.NoError(t, err)

	// Create valid session
	s2 := &session.Session{
		UserID:    "user-123",
		Token:     "valid-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err = repo.Create(s2)
	require.NoError(t, err)

	err = repo.DeleteExpired()
	assert.NoError(t, err)

	// Expired session should be gone
	found, err := repo.FindByID(s1.ID)
	assert.Error(t, err)
	assert.Nil(t, found)

	// Valid session should remain
	found, err = repo.FindByID(s2.ID)
	assert.NoError(t, err)
	assert.NotNil(t, found)
}

func TestSessionRepository_Count_Empty(t *testing.T) {
	repo := NewSessionRepository()

	count, err := repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestSessionRepository_Count_Multiple(t *testing.T) {
	repo := NewSessionRepository()

	for i := 0; i < 3; i++ {
		s := &session.Session{
			UserID:    "user-123",
			Token:     "token-" + string(rune('0'+i)),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := repo.Create(s)
		require.NoError(t, err)
	}

	count, err := repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestSessionRepository_ExistsByID_Exists(t *testing.T) {
	repo := NewSessionRepository()

	s := &session.Session{
		UserID:    "user-123",
		Token:     "session-token-12345678",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(s)
	require.NoError(t, err)

	exists, err := repo.ExistsByID(s.ID)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestSessionRepository_ExistsByID_NotFound(t *testing.T) {
	repo := NewSessionRepository()

	exists, err := repo.ExistsByID("non-existent-id")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestSessionRepository_ExistsByToken_Exists(t *testing.T) {
	repo := NewSessionRepository()

	s := &session.Session{
		UserID:    "user-123",
		Token:     "session-token-12345678",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(s)
	require.NoError(t, err)

	exists, err := repo.ExistsByToken(s.Token)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestSessionRepository_ExistsByToken_NotFound(t *testing.T) {
	repo := NewSessionRepository()

	exists, err := repo.ExistsByToken("non-existent-token")
	assert.NoError(t, err)
	assert.False(t, exists)
}
