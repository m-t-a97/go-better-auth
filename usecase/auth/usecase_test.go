package auth

import (
	"context"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
	"github.com/m-t-a97/go-better-auth/repository/memory"
)

func TestValidateSession_Valid(t *testing.T) {
	sessionRepo := memory.NewSessionRepository()

	// Create a session
	testSession := createTestSession()
	testSession.ExpiresAt = time.Now().Add(24 * time.Hour) // Make it valid
	sessionRepo.Create(testSession)

	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		sessionRepo,
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &ValidateSessionRequest{
		SessionToken: testSession.Token,
	}

	resp, err := service.ValidateSession(req)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}

	if resp == nil {
		t.Fatal("ValidateSession returned nil response")
	}

	if !resp.Valid {
		t.Error("Expected session to be valid")
	}

	if resp.Session == nil {
		t.Error("Expected session to be set")
	}
}

func TestValidateSession_Expired(t *testing.T) {
	sessionRepo := memory.NewSessionRepository()

	// Create an expired session
	testSession := createTestSession()
	testSession.ExpiresAt = time.Now().Add(-1 * time.Hour) // Make it expired
	sessionRepo.Create(testSession)

	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		sessionRepo,
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &ValidateSessionRequest{
		SessionToken: testSession.Token,
	}

	resp, err := service.ValidateSession(req)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}

	if resp.Valid {
		t.Error("Expected session to be invalid due to expiration")
	}
}

func TestValidateSession_NotFound(t *testing.T) {
	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &ValidateSessionRequest{
		SessionToken: "invalid-token",
	}

	resp, err := service.ValidateSession(req)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}

	if resp.Valid {
		t.Error("Expected session to be invalid")
	}

	if resp.Session != nil {
		t.Error("Expected session to be nil")
	}
}

func TestRefreshToken_Valid(t *testing.T) {
	sessionRepo := memory.NewSessionRepository()

	// Create a session
	testSession := createTestSession()
	testSession.ExpiresAt = time.Now().Add(24 * time.Hour)
	sessionRepo.Create(testSession)

	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		sessionRepo,
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	oldToken := testSession.Token

	req := &RefreshTokenRequest{
		SessionToken: oldToken,
		IPAddress:    "192.168.1.2",
		UserAgent:    "Chrome",
	}

	resp, err := service.RefreshToken(req)
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	if resp.Session == nil {
		t.Fatal("RefreshToken returned nil session")
	}

	if resp.Session.Token == oldToken {
		t.Error("Expected token to be refreshed")
	}

	if resp.Session.ExpiresAt.Before(time.Now().Add(23 * time.Hour)) {
		t.Error("Expected session expiration to be refreshed")
	}

	// Verify old token is no longer valid
	_, err = sessionRepo.FindByToken(oldToken)
	if err == nil {
		t.Error("Expected old token to be invalid")
	}

	// Verify new token exists
	foundSession, err := sessionRepo.FindByToken(resp.Session.Token)
	if err != nil || foundSession == nil {
		t.Error("Expected to find new session token")
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	sessionRepo := memory.NewSessionRepository()

	// Create an expired session
	testSession := createTestSession()
	testSession.ExpiresAt = time.Now().Add(-1 * time.Hour)
	sessionRepo.Create(testSession)

	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		sessionRepo,
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &RefreshTokenRequest{
		SessionToken: testSession.Token,
	}

	_, err := service.RefreshToken(req)
	if err == nil {
		t.Fatal("Expected error for expired session")
	}
}

func TestRequestPasswordReset_Valid(t *testing.T) {
	userRepo := memory.NewUserRepository()
	verificationRepo := memory.NewVerificationRepository()

	// Create a user
	testUser := createTestUser()
	userRepo.Create(testUser)

	service := NewService(
		createTestConfig(),
		userRepo,
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	req := &RequestPasswordResetRequest{
		Email: testUser.Email,
	}

	resp, err := service.RequestPasswordReset(context.Background(), req)
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	if resp.Verification == nil {
		t.Fatal("RequestPasswordReset returned nil verification")
	}

	if resp.Verification.Type != verification.TypePasswordReset {
		t.Errorf("Expected verification type %s, got %s", verification.TypePasswordReset, resp.Verification.Type)
	}

	if resp.Verification.Identifier != testUser.Email {
		t.Errorf("Expected identifier %s, got %s", testUser.Email, resp.Verification.Identifier)
	}

	// Verify token is stored
	v, err := verificationRepo.FindByToken(resp.Verification.Token)
	if err != nil || v == nil {
		t.Error("Expected verification token to be stored")
	}
}

func TestResetPassword_Valid(t *testing.T) {
	userRepo := memory.NewUserRepository()
	accountRepo := memory.NewAccountRepository()
	verificationRepo := memory.NewVerificationRepository()

	// Create a user with account
	testUser := createTestUser()
	userRepo.Create(testUser)

	oldPassword := "OldPassword123!"
	hashedOldPassword, _ := crypto.HashPassword(oldPassword)
	testAccount := createTestAccount(testUser.ID, &hashedOldPassword)
	accountRepo.Create(testAccount)

	// Create a password reset token
	resetToken := "reset-token-12345"
	hashedResetToken := crypto.HashVerificationToken(resetToken)
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      hashedResetToken,
		Type:       verification.TypePasswordReset,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	verificationRepo.Create(v)

	service := NewService(
		createTestConfig(), userRepo, memory.NewSessionRepository(), accountRepo, verificationRepo)

	req := &ResetPasswordRequest{
		ResetToken:  resetToken,
		NewPassword: "NewPassword456!",
	}

	resp, err := service.ResetPassword(req)
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	if resp.Message != "Password has been reset successfully" {
		t.Error("Expected reset password to succeed")
	}

	// Verify password was updated
	updatedAccount, err := accountRepo.FindByID(testAccount.ID)
	if err != nil || updatedAccount == nil {
		t.Fatal("Failed to find updated account")
	}

	// Verify old password doesn't work
	matches, err := crypto.VerifyPassword(oldPassword, *updatedAccount.Password)
	if err != nil || matches {
		t.Error("Old password should not match")
	}

	// Verify new password works
	matches, err = crypto.VerifyPassword(req.NewPassword, *updatedAccount.Password)
	if err != nil || !matches {
		t.Error("New password should match")
	}

	// Verify token is deleted
	_, err = verificationRepo.FindByHashedToken(resetToken)
	if err == nil {
		t.Error("Expected reset token to be deleted")
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &ResetPasswordRequest{
		ResetToken:  "invalid-token",
		NewPassword: "NewPassword456!",
	}

	_, err := service.ResetPassword(req)
	if err == nil {
		t.Fatal("Expected error for invalid token")
	}
}

func TestSendEmailVerification_Valid(t *testing.T) {
	verificationRepo := memory.NewVerificationRepository()

	config := createTestConfig()
	config.EmailVerification.Enabled = true

	service := NewService(
		config,
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	email := "verify@example.com"
	req := &SendEmailVerificationRequest{
		Email: email,
	}

	resp, err := service.SendEmailVerification(context.Background(), req)
	if err != nil {
		t.Fatalf("SendEmailVerification failed: %v", err)
	}

	if resp.Status == false {
		t.Fatal("SendEmailVerification returned false status")
	}
}

func TestVerifyEmail_Valid(t *testing.T) {
	userRepo := memory.NewUserRepository()
	verificationRepo := memory.NewVerificationRepository()

	// Create a user with unverified email
	testUser := createTestUser()
	testUser.EmailVerified = false
	userRepo.Create(testUser)

	// Create an email verification token
	verificationToken := "verify-token-12345"
	hashedVerificationToken := crypto.HashVerificationToken(verificationToken)
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      hashedVerificationToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	verificationRepo.Create(v)

	service := NewService(
		createTestConfig(), userRepo, memory.NewSessionRepository(), memory.NewAccountRepository(), verificationRepo)

	req := &VerifyEmailRequest{
		VerificationToken: verificationToken,
	}

	resp, err := service.VerifyEmail(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}

	if resp == nil {
		t.Fatal("VerifyEmail returned nil response")
	}

	if !resp.Status {
		t.Fatal("VerifyEmail returned false status")
	}

	// Verify email is now verified
	updatedUser, err := userRepo.FindByID(testUser.ID)
	if err != nil || updatedUser == nil {
		t.Fatal("Failed to find updated user")
	}

	if !updatedUser.EmailVerified {
		t.Error("Expected email to be verified")
	}

	// Verify token is deleted
	_, err = verificationRepo.FindByHashedToken(verificationToken)
	if err == nil {
		t.Error("Expected verification token to be deleted")
	}
}

func TestVerifyEmail_ExpiredToken(t *testing.T) {
	verificationRepo := memory.NewVerificationRepository()

	// Create an expired verification token
	expiredToken := "expired-verify-token"
	v := &verification.Verification{
		Identifier: "test@example.com",
		Token:      expiredToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt:  time.Now().Add(-2 * time.Hour),
		UpdatedAt:  time.Now().Add(-2 * time.Hour),
	}
	verificationRepo.Create(v)

	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	req := &VerifyEmailRequest{
		VerificationToken: expiredToken,
	}

	_, err := service.VerifyEmail(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for expired token")
	}
}

func TestGetProfile_Valid(t *testing.T) {
	userRepo := memory.NewUserRepository()

	// Create a user
	testUser := createTestUser()
	userRepo.Create(testUser)

	service := NewService(
		createTestConfig(),
		userRepo,
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &GetMeRequest{
		UserID: testUser.ID,
	}

	resp, err := service.GetMe(req)
	if err != nil {
		t.Fatalf("GetProfile failed: %v", err)
	}

	if resp.User == nil {
		t.Fatal("GetProfile returned nil user")
	}

	if resp.User.ID != testUser.ID {
		t.Errorf("Expected user ID %s, got %s", testUser.ID, resp.User.ID)
	}

	if resp.User.Email != testUser.Email {
		t.Errorf("Expected email %s, got %s", testUser.Email, resp.User.Email)
	}
}

func TestGetProfile_NotFound(t *testing.T) {
	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &GetMeRequest{
		UserID: "non-existent-id",
	}

	_, err := service.GetMe(req)
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
}

func TestPasswordHasher_Default(t *testing.T) {
	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Test that default password hasher is used
	password := "test-password-123"
	hash, err := service.passwordHasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if hash == "" {
		t.Error("Expected non-empty hash")
	}

	// Test verification
	valid, err := service.passwordHasher.Verify(password, hash)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}

	if !valid {
		t.Error("Expected password to be valid")
	}

	// Test invalid password
	valid, err = service.passwordHasher.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Failed to verify wrong password: %v", err)
	}

	if valid {
		t.Error("Expected wrong password to be invalid")
	}
}

func TestPasswordHasher_Custom(t *testing.T) {
	// Create custom hash and verify functions
	customHash := func(password string) (string, error) {
		return "custom-hash-" + password, nil
	}

	customVerify := func(password, hash string) bool {
		expected := "custom-hash-" + password
		return hash == expected
	}

	config := createTestConfig()
	config.EmailAndPassword = &domain.EmailPasswordConfig{
		Enabled: true,
		Password: &domain.PasswordConfig{
			Hash:   customHash,
			Verify: customVerify,
		},
	}

	service := NewService(
		config,
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Test custom password hasher
	password := "test-password-123"
	hash, err := service.passwordHasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	expectedHash := "custom-hash-" + password
	if hash != expectedHash {
		t.Errorf("Expected hash %q, got %q", expectedHash, hash)
	}

	// Test verification
	valid, err := service.passwordHasher.Verify(password, hash)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}

	if !valid {
		t.Error("Expected password to be valid")
	}

	// Test invalid password
	valid, err = service.passwordHasher.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Failed to verify wrong password: %v", err)
	}

	if valid {
		t.Error("Expected wrong password to be invalid")
	}
}

func TestPasswordHasher_CustomHashOnly(t *testing.T) {
	// Test with only custom hash function (should fall back to default hasher)
	customHash := func(password string) (string, error) {
		return "custom-hash-" + password, nil
	}

	config := createTestConfig()
	config.EmailAndPassword = &domain.EmailPasswordConfig{
		Enabled: true,
		Password: &domain.PasswordConfig{
			Hash: customHash,
			// No Verify function provided
		},
	}

	service := NewService(
		config,
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Should fall back to default hasher since verify is not provided
	password := "test-password-123"
	hash, err := service.passwordHasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Should be default hash, not custom
	if hash == "custom-hash-"+password {
		t.Error("Expected default hash, got custom hash")
	}
}
