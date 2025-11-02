package memory

import (
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAccountRepository(t *testing.T) {
	repo := NewAccountRepository()
	assert.NotNil(t, repo)
}

func TestAccountRepository_Create_Valid(t *testing.T) {
	repo := NewAccountRepository()

	token := "access-token-123"
	a := &account.Account{
		UserID:      "user-123",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err := repo.Create(a)
	assert.NoError(t, err)
	assert.NotEmpty(t, a.ID)
	assert.False(t, a.CreatedAt.IsZero())
	assert.False(t, a.UpdatedAt.IsZero())
}

func TestAccountRepository_Create_Nil(t *testing.T) {
	repo := NewAccountRepository()

	err := repo.Create(nil)
	assert.Error(t, err)
}

func TestAccountRepository_FindByID_Exists(t *testing.T) {
	repo := NewAccountRepository()

	token := "access-token-123"
	a := &account.Account{
		UserID:      "user-123",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err := repo.Create(a)
	require.NoError(t, err)

	found, err := repo.FindByID(a.ID)
	assert.NoError(t, err)
	assert.Equal(t, a.ID, found.ID)
	assert.Equal(t, a.UserID, found.UserID)
}

func TestAccountRepository_FindByID_NotFound(t *testing.T) {
	repo := NewAccountRepository()

	found, err := repo.FindByID("non-existent-id")
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestAccountRepository_FindByUserIDAndProvider_Exists(t *testing.T) {
	repo := NewAccountRepository()

	token := "access-token-123"
	a := &account.Account{
		UserID:      "user-123",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err := repo.Create(a)
	require.NoError(t, err)

	found, err := repo.FindByUserIDAndProvider("user-123", account.ProviderGoogle)
	assert.NoError(t, err)
	assert.Equal(t, a.ID, found.ID)
	assert.Equal(t, account.ProviderGoogle, found.ProviderID)
}

func TestAccountRepository_FindByUserIDAndProvider_NotFound(t *testing.T) {
	repo := NewAccountRepository()

	found, err := repo.FindByUserIDAndProvider("user-123", account.ProviderGoogle)
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestAccountRepository_FindByUserID_Multiple(t *testing.T) {
	repo := NewAccountRepository()

	userID := "user-123"
	for i, provider := range []account.ProviderType{account.ProviderGoogle, account.ProviderGitHub} {
		token := "token-" + string(rune('0'+i))
		a := &account.Account{
			UserID:      userID,
			ProviderID:  provider,
			AccountID:   string(rune('0' + i)),
			AccessToken: &token,
		}
		err := repo.Create(a)
		require.NoError(t, err)
	}

	accounts, err := repo.FindByUserID(userID)
	assert.NoError(t, err)
	assert.Len(t, accounts, 2)

	for _, a := range accounts {
		assert.Equal(t, userID, a.UserID)
	}
}

func TestAccountRepository_Update_Valid(t *testing.T) {
	repo := NewAccountRepository()

	token := "access-token-123"
	a := &account.Account{
		UserID:      "user-123",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err := repo.Create(a)
	require.NoError(t, err)

	newToken := "updated-token"
	a.AccessToken = &newToken
	err = repo.Update(a)
	assert.NoError(t, err)

	found, err := repo.FindByID(a.ID)
	require.NoError(t, err)
	assert.Equal(t, &newToken, found.AccessToken)
}

func TestAccountRepository_Delete_Valid(t *testing.T) {
	repo := NewAccountRepository()

	token := "access-token-123"
	a := &account.Account{
		UserID:      "user-123",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err := repo.Create(a)
	require.NoError(t, err)

	err = repo.Delete(a.ID)
	assert.NoError(t, err)

	found, err := repo.FindByID(a.ID)
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestAccountRepository_DeleteByUserID(t *testing.T) {
	repo := NewAccountRepository()

	userID := "user-123"
	for i := 0; i < 2; i++ {
		token := "token-" + string(rune('0'+i))
		a := &account.Account{
			UserID:      userID,
			ProviderID:  account.ProviderType("provider-" + string(rune('0'+i))),
			AccountID:   string(rune('0' + i)),
			AccessToken: &token,
		}
		err := repo.Create(a)
		require.NoError(t, err)
	}

	err := repo.DeleteByUserID(userID)
	assert.NoError(t, err)

	accounts, err := repo.FindByUserID(userID)
	assert.NoError(t, err)
	assert.Empty(t, accounts)
}

func TestAccountRepository_Count(t *testing.T) {
	repo := NewAccountRepository()

	count, err := repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	token := "access-token-123"
	a := &account.Account{
		UserID:      "user-123",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err = repo.Create(a)
	require.NoError(t, err)

	count, err = repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestAccountRepository_ExistsByID(t *testing.T) {
	repo := NewAccountRepository()

	token := "access-token-123"
	a := &account.Account{
		UserID:      "user-123",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err := repo.Create(a)
	require.NoError(t, err)

	exists, err := repo.ExistsByID(a.ID)
	assert.NoError(t, err)
	assert.True(t, exists)

	exists, err = repo.ExistsByID("non-existent-id")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestAccountRepository_ExistsByUserIDAndProvider(t *testing.T) {
	repo := NewAccountRepository()

	token := "access-token-123"
	a := &account.Account{
		UserID:      "user-123",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err := repo.Create(a)
	require.NoError(t, err)

	exists, err := repo.ExistsByUserIDAndProvider("user-123", account.ProviderGoogle)
	assert.NoError(t, err)
	assert.True(t, exists)

	exists, err = repo.ExistsByUserIDAndProvider("user-123", account.ProviderGitHub)
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestAccount_IsTokenExpired_False(t *testing.T) {
	a := &account.Account{
		AccessTokenExpiresAt: timePtr(time.Now().Add(1 * time.Hour)),
	}

	assert.False(t, a.IsTokenExpired())
}

func TestAccount_IsTokenExpired_True(t *testing.T) {
	a := &account.Account{
		AccessTokenExpiresAt: timePtr(time.Now().Add(-1 * time.Hour)),
	}

	assert.True(t, a.IsTokenExpired())
}

func TestAccount_IsRefreshTokenExpired(t *testing.T) {
	a := &account.Account{
		RefreshTokenExpiresAt: timePtr(time.Now().Add(-1 * time.Hour)),
	}

	assert.True(t, a.IsRefreshTokenExpired())
}

func timePtr(t time.Time) *time.Time {
	return &t
}
