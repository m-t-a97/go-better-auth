//go:build cgo
// +build cgo

package sqlite

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/m-t-a97/go-better-auth/domain"
)

// TestNewSQLiteAdapter tests adapter creation
func TestNewSQLiteAdapter(t *testing.T) {
	// Use in-memory database for testing
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	assert.NotNil(t, adapter)

	defer adapter.Close()

	// Run migrations
	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)
}

// TestUserRepository tests user repository operations
func TestUserRepository(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	userRepo := NewSQLiteUserRepository(adapter.GetDB())

	// Test Create
	user := &domain.User{
		ID:            uuid.New().String(),
		Name:          "Test User",
		Email:         "test@example.com",
		EmailVerified: false,
		Image:         nil,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err = userRepo.Create(ctx, user)
	assert.NoError(t, err)

	// Test FindByEmail
	foundUser, err := userRepo.FindByEmail(ctx, user.Email)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, user.Email, foundUser.Email)

	// Test FindByID
	foundUser, err = userRepo.FindByID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, foundUser.Email)

	// Test Update
	foundUser.Name = "Updated Name"
	err = userRepo.Update(ctx, foundUser)
	assert.NoError(t, err)

	updatedUser, err := userRepo.FindByID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", updatedUser.Name)

	// Test Delete
	err = userRepo.Delete(ctx, user.ID)
	assert.NoError(t, err)

	_, err = userRepo.FindByID(ctx, user.ID)
	assert.Equal(t, domain.ErrUserNotFound, err)
}

// TestSessionRepository tests session repository operations
func TestSessionRepository(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	userRepo := NewSQLiteUserRepository(adapter.GetDB())
	sessionRepo := NewSQLiteSessionRepository(adapter.GetDB())

	// Create a user first
	user := &domain.User{
		ID:        uuid.New().String(),
		Name:      "Test User",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Test Create session
	ip := "127.0.0.1"
	ua := "Test Agent"
	session := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     "test-token-" + uuid.New().String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IPAddress: &ip,
		UserAgent: &ua,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = sessionRepo.Create(ctx, session)
	assert.NoError(t, err)

	// Test FindByToken
	foundSession, err := sessionRepo.FindByToken(ctx, session.Token)
	assert.NoError(t, err)
	assert.Equal(t, session.ID, foundSession.ID)
	assert.Equal(t, session.UserID, foundSession.UserID)

	// Test FindByUserID
	sessions, err := sessionRepo.FindByUserID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, session.ID, sessions[0].ID)

	// Test Update
	foundSession.ExpiresAt = time.Now().Add(48 * time.Hour)
	err = sessionRepo.Update(ctx, foundSession)
	assert.NoError(t, err)

	updatedSession, err := sessionRepo.FindByToken(ctx, session.Token)
	assert.NoError(t, err)
	assert.True(t, updatedSession.ExpiresAt.After(foundSession.ExpiresAt.Add(-1*time.Hour)))

	// Test Delete
	err = sessionRepo.Delete(ctx, session.ID)
	assert.NoError(t, err)

	_, err = sessionRepo.FindByToken(ctx, session.Token)
	assert.Equal(t, domain.ErrInvalidToken, err)

	// Test DeleteByToken
	session2 := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     "test-token-2-" + uuid.New().String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = sessionRepo.Create(ctx, session2)
	require.NoError(t, err)

	err = sessionRepo.DeleteByToken(ctx, session2.Token)
	assert.NoError(t, err)

	_, err = sessionRepo.FindByToken(ctx, session2.Token)
	assert.Equal(t, domain.ErrInvalidToken, err)
}

// TestAccountRepository tests account repository operations
func TestAccountRepository(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	userRepo := NewSQLiteUserRepository(adapter.GetDB())
	accountRepo := NewSQLiteAccountRepository(adapter.GetDB())

	// Create a user first
	user := &domain.User{
		ID:        uuid.New().String(),
		Name:      "Test User",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Test Create account
	token := "access-token"
	account := &domain.Account{
		ID:          uuid.New().String(),
		UserID:      user.ID,
		AccountID:   "google-123",
		ProviderId:  "google",
		AccessToken: &token,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = accountRepo.Create(ctx, account)
	assert.NoError(t, err)

	// Test FindByUserIDAndProvider
	foundAccount, err := accountRepo.FindByUserIDAndProvider(ctx, user.ID, "google")
	assert.NoError(t, err)
	assert.Equal(t, account.ID, foundAccount.ID)
	assert.Equal(t, "google-123", foundAccount.AccountID)

	// Test FindByProviderAccountID
	foundAccount, err = accountRepo.FindByProviderAccountID(ctx, "google", "google-123")
	assert.NoError(t, err)
	assert.Equal(t, account.ID, foundAccount.ID)

	// Test Update
	newToken := "new-access-token"
	foundAccount.AccessToken = &newToken
	err = accountRepo.Update(ctx, foundAccount)
	assert.NoError(t, err)

	updatedAccount, err := accountRepo.FindByUserIDAndProvider(ctx, user.ID, "google")
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token", *updatedAccount.AccessToken)

	// Test ListByUserID
	account2 := &domain.Account{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		AccountID:  "github-456",
		ProviderId: "github",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	err = accountRepo.Create(ctx, account2)
	require.NoError(t, err)

	accounts, err := accountRepo.ListByUserID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Len(t, accounts, 2)

	// Test Delete
	err = accountRepo.Delete(ctx, account.ID)
	assert.NoError(t, err)

	_, err = accountRepo.FindByUserIDAndProvider(ctx, user.ID, "google")
	assert.Equal(t, domain.ErrUserNotFound, err)
}

// TestVerificationRepository tests verification repository operations
func TestVerificationRepository(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	verificationRepo := NewSQLiteVerificationRepository(adapter.GetDB())

	// Test Create
	verification := &domain.Verification{
		ID:         uuid.New().String(),
		Identifier: "email",
		Value:      "test@example.com",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
	}

	err = verificationRepo.Create(ctx, verification)
	assert.NoError(t, err)

	// Test FindByIdentifierAndValue
	foundVerification, err := verificationRepo.FindByIdentifierAndValue(ctx, "email", "test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, verification.ID, foundVerification.ID)

	// Test FindByValue (identifier empty)
	foundVerification, err = verificationRepo.FindByIdentifierAndValue(ctx, "", "test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, verification.ID, foundVerification.ID)

	// Test Delete
	err = verificationRepo.Delete(ctx, verification.ID)
	assert.NoError(t, err)

	_, err = verificationRepo.FindByIdentifierAndValue(ctx, "email", "test@example.com")
	assert.Equal(t, domain.ErrInvalidToken, err)
}

// TestMFARepository tests MFA repository operations
func TestMFARepository(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMFAMigrationSQL)
	require.NoError(t, err)

	userRepo := NewSQLiteUserRepository(adapter.GetDB())
	mfaRepo := NewTwoFactorAuthAdapter(adapter.GetDB())

	// Create a user first
	user := &domain.User{
		ID:        uuid.New().String(),
		Name:      "Test User",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Test Create
	mfa := &domain.TwoFactorAuth{
		UserID:      user.ID,
		Method:      domain.TOTP,
		IsEnabled:   false,
		BackupCodes: []string{"code1", "code2"},
	}

	err = mfaRepo.Create(ctx, mfa)
	assert.NoError(t, err)
	assert.NotEmpty(t, mfa.ID)

	// Test FindByUserID
	foundMFA, err := mfaRepo.FindByUserID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, mfa.ID, foundMFA.ID)
	assert.Equal(t, domain.TOTP, foundMFA.Method)

	// Test FindByUserIDAndMethod
	foundMFA, err = mfaRepo.FindByUserIDAndMethod(ctx, user.ID, domain.TOTP)
	assert.NoError(t, err)
	assert.Equal(t, mfa.ID, foundMFA.ID)

	// Test Update
	foundMFA.IsEnabled = true
	err = mfaRepo.Update(ctx, foundMFA)
	assert.NoError(t, err)

	updatedMFA, err := mfaRepo.FindByUserID(ctx, user.ID)
	assert.NoError(t, err)
	assert.True(t, updatedMFA.IsEnabled)

	// Test Delete
	err = mfaRepo.Delete(ctx, mfa.ID)
	assert.NoError(t, err)

	_, err = mfaRepo.FindByUserID(ctx, user.ID)
	assert.Equal(t, domain.ErrNotFound, err)
}

// TestTOTPRepository tests TOTP repository operations
func TestTOTPRepository(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMFAMigrationSQL)
	require.NoError(t, err)

	userRepo := NewSQLiteUserRepository(adapter.GetDB())
	totpRepo := NewTOTPSecretAdapter(adapter.GetDB())

	// Create a user first
	user := &domain.User{
		ID:        uuid.New().String(),
		Name:      "Test User",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Test Create
	secret := &domain.TOTPSecret{
		UserID:      user.ID,
		Secret:      "JBSWY3DPEBLW64TMMQ======",
		QRCode:      "data:image/png;base64,...",
		IsVerified:  false,
		BackupCodes: []string{"code1", "code2"},
	}

	err = totpRepo.Create(ctx, secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, secret.ID)

	// Test FindByUserID
	foundSecret, err := totpRepo.FindByUserID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, secret.ID, foundSecret.ID)
	assert.Equal(t, secret.Secret, foundSecret.Secret)

	// Test Update
	foundSecret.IsVerified = true
	err = totpRepo.Update(ctx, foundSecret)
	assert.NoError(t, err)

	updatedSecret, err := totpRepo.FindByUserID(ctx, user.ID)
	assert.NoError(t, err)
	assert.True(t, updatedSecret.IsVerified)

	// Test Delete
	err = totpRepo.Delete(ctx, secret.ID)
	assert.NoError(t, err)

	_, err = totpRepo.FindByUserID(ctx, user.ID)
	assert.Equal(t, domain.ErrNotFound, err)
}

// TestMFAChallengeRepository tests MFA challenge repository operations
func TestMFAChallengeRepository(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMFAMigrationSQL)
	require.NoError(t, err)

	userRepo := NewSQLiteUserRepository(adapter.GetDB())
	challengeRepo := NewMFAChallengeAdapter(adapter.GetDB())

	// Create a user first
	user := &domain.User{
		ID:        uuid.New().String(),
		Name:      "Test User",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Test Create
	challenge := &domain.MFAChallenge{
		UserID:    user.ID,
		Method:    domain.TOTP,
		Challenge: "123456",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	err = challengeRepo.Create(ctx, challenge)
	assert.NoError(t, err)
	assert.NotEmpty(t, challenge.ID)

	// Test FindByID
	foundChallenge, err := challengeRepo.FindByID(ctx, challenge.ID)
	assert.NoError(t, err)
	assert.Equal(t, challenge.ID, foundChallenge.ID)

	// Test FindByUserIDAndMethod
	foundChallenge, err = challengeRepo.FindByUserIDAndMethod(ctx, user.ID, domain.TOTP)
	assert.NoError(t, err)
	assert.Equal(t, challenge.ID, foundChallenge.ID)

	// Test Delete
	err = challengeRepo.Delete(ctx, challenge.ID)
	assert.NoError(t, err)

	_, err = challengeRepo.FindByID(ctx, challenge.ID)
	assert.Equal(t, domain.ErrNotFound, err)
}

// TestDeleteExpiredSessions tests expired session cleanup
func TestDeleteExpiredSessions(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	userRepo := NewSQLiteUserRepository(adapter.GetDB())
	sessionRepo := NewSQLiteSessionRepository(adapter.GetDB())

	// Create a user
	user := &domain.User{
		ID:        uuid.New().String(),
		Name:      "Test User",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Create expired session
	expiredSession := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     "expired-token",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = sessionRepo.Create(ctx, expiredSession)
	require.NoError(t, err)

	// Create valid session
	validSession := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     "valid-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = sessionRepo.Create(ctx, validSession)
	require.NoError(t, err)

	// Delete expired sessions
	err = sessionRepo.DeleteExpired(ctx)
	assert.NoError(t, err)

	// Expired session should not be found
	_, err = sessionRepo.FindByToken(ctx, expiredSession.Token)
	assert.Equal(t, domain.ErrInvalidToken, err)

	// Valid session should still exist
	foundSession, err := sessionRepo.FindByToken(ctx, validSession.Token)
	assert.NoError(t, err)
	assert.Equal(t, validSession.ID, foundSession.ID)
}

// TestClosingAdapter ensures adapter cleanup works
func TestClosingAdapter(t *testing.T) {
	adapter, err := NewSQLiteAdapter(":memory:")
	require.NoError(t, err)

	err = adapter.Close()
	assert.NoError(t, err)
}

// TestUsingTemporaryFile tests SQLite with a temporary file
func TestUsingTemporaryFile(t *testing.T) {
	tempFile := t.TempDir() + "/test.db"

	adapter, err := NewSQLiteAdapter(tempFile)
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()
	_, err = adapter.GetDB().ExecContext(ctx, SQLiteMigrationSQL)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(tempFile)
	assert.NoError(t, err)
}
