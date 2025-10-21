package auth

import (
	"testing"
	"time"

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
		userRepo,
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	req := &RequestPasswordResetRequest{
		Email: testUser.Email,
	}

	resp, err := service.RequestPasswordReset(req)
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
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      resetToken,
		Type:       verification.TypePasswordReset,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	verificationRepo.Create(v)

	service := NewService(userRepo, memory.NewSessionRepository(), accountRepo, verificationRepo)

	req := &ResetPasswordRequest{
		ResetToken:  resetToken,
		NewPassword: "NewPassword456!",
	}

	resp, err := service.ResetPassword(req)
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	if !resp.Success {
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
	_, err = verificationRepo.FindByToken(resetToken)
	if err == nil {
		t.Error("Expected reset token to be deleted")
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	service := NewService(
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

func TestRequestEmailVerification_Valid(t *testing.T) {
	verificationRepo := memory.NewVerificationRepository()

	service := NewService(
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	email := "verify@example.com"
	req := &RequestEmailVerificationRequest{
		Email: email,
	}

	resp, err := service.RequestEmailVerification(req)
	if err != nil {
		t.Fatalf("RequestEmailVerification failed: %v", err)
	}

	if resp.Verification == nil {
		t.Fatal("RequestEmailVerification returned nil verification")
	}

	if resp.Verification.Type != verification.TypeEmailVerification {
		t.Errorf("Expected verification type %s, got %s", verification.TypeEmailVerification, resp.Verification.Type)
	}

	if resp.Verification.Identifier != email {
		t.Errorf("Expected identifier %s, got %s", email, resp.Verification.Identifier)
	}

	// Verify token is stored
	v, err := verificationRepo.FindByToken(resp.Verification.Token)
	if err != nil || v == nil {
		t.Error("Expected verification token to be stored")
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
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      verificationToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	verificationRepo.Create(v)

	service := NewService(userRepo, memory.NewSessionRepository(), memory.NewAccountRepository(), verificationRepo)

	req := &VerifyEmailRequest{
		VerificationToken: verificationToken,
	}

	resp, err := service.VerifyEmail(req)
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}

	if !resp.Success {
		t.Error("Expected email verification to succeed")
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
	_, err = verificationRepo.FindByToken(verificationToken)
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
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	req := &VerifyEmailRequest{
		VerificationToken: expiredToken,
	}

	_, err := service.VerifyEmail(req)
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
		userRepo,
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &GetProfileRequest{
		UserID: testUser.ID,
	}

	resp, err := service.GetProfile(req)
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
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &GetProfileRequest{
		UserID: "non-existent-id",
	}

	_, err := service.GetProfile(req)
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
}
