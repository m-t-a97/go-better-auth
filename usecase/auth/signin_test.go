package auth

import (
	"context"
	"testing"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
	"github.com/GoBetterAuth/go-better-auth/repository/memory"
)

func TestSignIn_Valid(t *testing.T) {
	userRepo := memory.NewUserRepository()
	sessionRepo := memory.NewSessionRepository()
	accountRepo := memory.NewAccountRepository()
	verificationRepo := memory.NewVerificationRepository()

	// Create a user
	password := "ValidPassword123!"
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Manually create user and account
	testUser := createTestUser()
	if err := userRepo.Create(testUser); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	testAccount := createTestAccount(testUser.ID, &hashedPassword)
	if err := accountRepo.Create(testAccount); err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	service := NewService(
		createTestConfig(), userRepo, sessionRepo, accountRepo, verificationRepo)

	req := &SignInRequest{
		Email:     testUser.Email,
		Password:  password,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	resp, err := service.SignIn(context.Background(), req)
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}

	if resp == nil || resp.Session == nil {
		t.Fatal("SignIn returned nil session")
	}

	if resp.Session.UserID != testUser.ID {
		t.Errorf("Expected UserID %s, got %s", testUser.ID, resp.Session.UserID)
	}

	if resp.Session.Token == "" {
		t.Error("Expected session token to be set")
	}

	if resp.Session.ExpiresAt.IsZero() {
		t.Error("Expected session ExpiresAt to be set")
	}
}

func TestSignIn_InvalidPassword(t *testing.T) {
	userRepo := memory.NewUserRepository()
	accountRepo := memory.NewAccountRepository()

	// Create a user with a specific password
	password := "ValidPassword123!"
	hashedPassword, _ := crypto.HashPassword(password)

	testUser := createTestUser()
	userRepo.Create(testUser)

	testAccount := createTestAccount(testUser.ID, &hashedPassword)
	accountRepo.Create(testAccount)

	service := NewService(
		createTestConfig(), userRepo, memory.NewSessionRepository(), accountRepo, memory.NewVerificationRepository())

	req := &SignInRequest{
		Email:     testUser.Email,
		Password:  "WrongPassword123!",
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	_, err := service.SignIn(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for invalid password, got nil")
	}
}

func TestSignIn_UserNotFound(t *testing.T) {
	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &SignInRequest{
		Email:     "nonexistent@example.com",
		Password:  "SomePassword123!",
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	_, err := service.SignIn(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for non-existent user, got nil")
	}
}

func TestSignIn_AccountNotFound(t *testing.T) {
	userRepo := memory.NewUserRepository()

	// Create a user without an account
	testUser := createTestUser()
	userRepo.Create(testUser)

	service := NewService(
		createTestConfig(), userRepo, memory.NewSessionRepository(), memory.NewAccountRepository(), memory.NewVerificationRepository())

	req := &SignInRequest{
		Email:     testUser.Email,
		Password:  "SomePassword123!",
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	_, err := service.SignIn(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for user without account, got nil")
	}
}

func TestSignInRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     *SignInRequest
		wantErr bool
	}{
		{
			name: "valid",
			req: &SignInRequest{
				Email:    "user@example.com",
				Password: "ValidPassword123!",
			},
			wantErr: false,
		},
		{
			name: "missing_email",
			req: &SignInRequest{
				Password: "ValidPassword123!",
			},
			wantErr: true,
		},
		{
			name: "missing_password",
			req: &SignInRequest{
				Email: "user@example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignOut_Valid(t *testing.T) {
	sessionRepo := memory.NewSessionRepository()

	// Create a test session
	testSession := createTestSession()
	sessionRepo.Create(testSession)

	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		sessionRepo,
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &SignOutRequest{
		SessionToken: testSession.Token,
	}

	err := service.SignOut(req)
	if err != nil {
		t.Fatalf("SignOut failed: %v", err)
	}

	// Verify session is deleted
	_, err = sessionRepo.FindByToken(testSession.Token)
	if err == nil {
		t.Fatal("Expected session to be deleted, but it was found")
	}
}

func TestSignOut_InvalidToken(t *testing.T) {
	service := NewService(
		createTestConfig(),
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	req := &SignOutRequest{
		SessionToken: "invalid-token",
	}

	err := service.SignOut(req)
	if err == nil {
		t.Fatal("Expected error for invalid session token, got nil")
	}
}

func TestSignIn_WithDisabledSignUp(t *testing.T) {
	// Verify that existing users can still sign in even when signup is disabled
	userRepo := memory.NewUserRepository()
	sessionRepo := memory.NewSessionRepository()
	accountRepo := memory.NewAccountRepository()
	verificationRepo := memory.NewVerificationRepository()

	// Create a user
	password := "ValidPassword123!"
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Manually create user and account
	testUser := createTestUser()
	if err := userRepo.Create(testUser); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	testAccount := createTestAccount(testUser.ID, &hashedPassword)
	if err := accountRepo.Create(testAccount); err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	// Create config with disabled signup
	config := createTestConfig()
	config.EmailAndPassword = &domain.EmailPasswordConfig{
		Enabled:                  true,
		DisableSignUp:            true,
		RequireEmailVerification: false,
		MinPasswordLength:        8,
		MaxPasswordLength:        128,
	}

	service := NewService(config, userRepo, sessionRepo, accountRepo, verificationRepo)

	req := &SignInRequest{
		Email:     testUser.Email,
		Password:  password,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	resp, err := service.SignIn(context.Background(), req)
	if err != nil {
		t.Fatalf("SignIn failed when signup is disabled: %v", err)
	}

	if resp == nil || resp.Session == nil {
		t.Fatal("SignIn returned nil response when signup is disabled")
	}

	if resp.User.Email != testUser.Email {
		t.Errorf("Expected user email %s, got %s", testUser.Email, resp.User.Email)
	}
}
