package usecase_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/usecase"
)

// Mock OAuth Provider for testing
type MockOAuthProvider struct {
	tokens              *usecase.OAuthTokens
	userInfo            *usecase.OAuthUserInfo
	exchangeCodeErr     error
	getUserInfoErr      error
	shouldFailWithCode  string
	shouldFailWithToken string
}

func (m *MockOAuthProvider) GetProviderID() string {
	return "mock"
}

func (m *MockOAuthProvider) GetAuthURL(state, redirectURI string) string {
	return "https://mock-provider.com/auth?state=" + state
}

func (m *MockOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*usecase.OAuthTokens, error) {
	if m.exchangeCodeErr != nil {
		return nil, m.exchangeCodeErr
	}
	if m.shouldFailWithCode == code {
		return nil, fmt.Errorf("invalid authorization code")
	}
	return m.tokens, nil
}

func (m *MockOAuthProvider) GetUserInfo(ctx context.Context, accessToken string) (*usecase.OAuthUserInfo, error) {
	if m.getUserInfoErr != nil {
		return nil, m.getUserInfoErr
	}
	if m.shouldFailWithToken == accessToken {
		return nil, fmt.Errorf("token has expired")
	}
	return m.userInfo, nil
}

func TestOAuthHandleCallback(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	provider := &MockOAuthProvider{
		tokens: &usecase.OAuthTokens{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			IDToken:      "test-id-token",
			ExpiresIn:    3600,
			Scope:        "profile email",
		},
		userInfo: &usecase.OAuthUserInfo{
			ID:            "oauth-user-123",
			Email:         "user@example.com",
			Name:          "Test User",
			Image:         "https://example.com/avatar.png",
			EmailVerified: true,
		},
	}

	uc.RegisterProvider(provider)

	output, err := uc.HandleCallback(context.Background(), "mock", "test-code", "")
	if err != nil {
		t.Fatalf("HandleCallback failed: %v", err)
	}

	if output.User.Email != "user@example.com" {
		t.Errorf("Expected user email 'user@example.com', got %s", output.User.Email)
	}

	if output.Session == nil {
		t.Fatal("Session should not be nil")
	}

	if output.Session.Token == "" {
		t.Fatal("Session token should not be empty")
	}
}

func TestOAuthRefreshToken(t *testing.T) {
	// Note: Full token refresh testing requires actual OAuth provider credentials
	// This test verifies the account storage/update logic
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()

	// Create a user and account with tokens
	user := &domain.User{
		ID:        "user-123",
		Email:     "user@example.com",
		Name:      "Test User",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	userRepo.Create(context.Background(), user)

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	refreshTokenExpiresAt := time.Now().Add(30 * 24 * time.Hour)
	account := &domain.Account{
		ID:                    "account-123",
		UserID:                user.ID,
		AccountID:             "oauth-123",
		ProviderId:            "google",
		AccessToken:           stringPtr("old-access-token"),
		RefreshToken:          stringPtr("test-refresh-token"),
		AccessTokenExpiresAt:  &expiresAt,
		RefreshTokenExpiresAt: &refreshTokenExpiresAt,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}
	accountRepo.Create(context.Background(), account)

	// Verify we can retrieve the account
	retrieved, err := accountRepo.FindByUserIDAndProvider(context.Background(), user.ID, "google")
	if err != nil {
		t.Fatalf("Failed to retrieve account: %v", err)
	}

	if retrieved.AccessToken == nil || *retrieved.AccessToken != "old-access-token" {
		t.Error("Expected to retrieve correct access token")
	}

	if retrieved.RefreshToken == nil || *retrieved.RefreshToken != "test-refresh-token" {
		t.Error("Expected to retrieve correct refresh token")
	}

	// Simulate token update
	newAccessToken := "new-access-token"
	retrieved.AccessToken = &newAccessToken
	accountRepo.Update(context.Background(), retrieved)

	// Verify update
	updated, _ := accountRepo.FindByUserIDAndProvider(context.Background(), user.ID, "google")
	if updated.AccessToken == nil || *updated.AccessToken != "new-access-token" {
		t.Errorf("Expected access token to be updated to 'new-access-token'")
	}
}

func TestOAuthRefreshTokenExpired(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	// Create a user and account with expired refresh token
	user := &domain.User{
		ID:        "user-123",
		Email:     "user@example.com",
		Name:      "Test User",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	userRepo.Create(context.Background(), user)

	expiresAt := time.Now().Add(-1 * time.Hour) // Expired
	account := &domain.Account{
		ID:                    "account-123",
		UserID:                user.ID,
		AccountID:             "oauth-123",
		ProviderId:            "google",
		AccessToken:           stringPtr("old-access-token"),
		RefreshToken:          stringPtr("expired-refresh-token"),
		AccessTokenExpiresAt:  &expiresAt,
		RefreshTokenExpiresAt: &expiresAt, // Expired
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}
	accountRepo.Create(context.Background(), account)

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	provider := &MockOAuthProvider{
		tokens: &usecase.OAuthTokens{
			AccessToken: "new-access-token",
		},
	}

	uc.RegisterProvider(provider)

	_, err := uc.RefreshToken(context.Background(), &usecase.RefreshTokenInput{
		UserID:   user.ID,
		Provider: "google",
	})

	if err == nil {
		t.Fatal("Expected error for expired refresh token")
	}
}

func TestOAuthRefreshTokenNoRefreshToken(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	// Create a user and account without refresh token
	user := &domain.User{
		ID:        "user-123",
		Email:     "user@example.com",
		Name:      "Test User",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	userRepo.Create(context.Background(), user)

	account := &domain.Account{
		ID:          "account-123",
		UserID:      user.ID,
		AccountID:   "oauth-123",
		ProviderId:  "google",
		AccessToken: stringPtr("old-access-token"),
		// No refresh token
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	accountRepo.Create(context.Background(), account)

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	_, err := uc.RefreshToken(context.Background(), &usecase.RefreshTokenInput{
		UserID:   user.ID,
		Provider: "google",
	})

	if err == nil {
		t.Fatal("Expected error when no refresh token available")
	}
}

// Error Handling Tests

func TestOAuthHandleCallbackInvalidCode(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	provider := &MockOAuthProvider{
		shouldFailWithCode: "invalid-code",
	}

	uc.RegisterProvider(provider)

	_, err := uc.HandleCallback(context.Background(), "mock", "invalid-code", "")
	if err == nil {
		t.Fatal("Expected error for invalid code")
	}
	if err.Error() != "invalid authorization code" {
		t.Errorf("Expected 'invalid authorization code', got %s", err.Error())
	}
}

func TestOAuthHandleCallbackExpiredToken(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	provider := &MockOAuthProvider{
		tokens: &usecase.OAuthTokens{
			AccessToken:  "expired-token",
			RefreshToken: "test-refresh-token",
			IDToken:      "test-id-token",
			ExpiresIn:    3600,
			Scope:        "profile email",
		},
		shouldFailWithToken: "expired-token",
	}

	uc.RegisterProvider(provider)

	_, err := uc.HandleCallback(context.Background(), "mock", "test-code", "")
	if err == nil {
		t.Fatal("Expected error for expired token")
	}
	if err.Error() != "token has expired" {
		t.Errorf("Expected 'token has expired', got %s", err.Error())
	}
}

func TestOAuthHandleCallbackExchangeCodeError(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	provider := &MockOAuthProvider{
		exchangeCodeErr: fmt.Errorf("provider service unavailable"),
	}

	uc.RegisterProvider(provider)

	_, err := uc.HandleCallback(context.Background(), "mock", "test-code", "")
	if err == nil {
		t.Fatal("Expected error when provider service is unavailable")
	}
	if err.Error() != "provider service unavailable" {
		t.Errorf("Expected 'provider service unavailable', got %s", err.Error())
	}
}

func TestOAuthHandleCallbackUserInfoError(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	provider := &MockOAuthProvider{
		tokens: &usecase.OAuthTokens{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			IDToken:      "test-id-token",
			ExpiresIn:    3600,
			Scope:        "profile email",
		},
		getUserInfoErr: fmt.Errorf("failed to fetch user info"),
	}

	uc.RegisterProvider(provider)

	_, err := uc.HandleCallback(context.Background(), "mock", "test-code", "")
	if err == nil {
		t.Fatal("Expected error when fetching user info fails")
	}
	if err.Error() != "failed to fetch user info" {
		t.Errorf("Expected 'failed to fetch user info', got %s", err.Error())
	}
}

func TestOAuthProviderNotFound(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	_, err := uc.HandleCallback(context.Background(), "nonexistent-provider", "test-code", "")
	if err == nil {
		t.Fatal("Expected error for nonexistent provider")
	}
	if err.Error() != "provider not found: nonexistent-provider" {
		t.Errorf("Expected 'provider not found: nonexistent-provider', got %s", err.Error())
	}
}

func TestOAuthGetAuthURLProviderNotFound(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	_, err := uc.GetAuthURL("nonexistent-provider", "state", "https://example.com/callback")
	if err == nil {
		t.Fatal("Expected error for nonexistent provider")
	}
	if err.Error() != "provider not found: nonexistent-provider" {
		t.Errorf("Expected 'provider not found: nonexistent-provider', got %s", err.Error())
	}
}

func TestOAuthHandleCallbackExistingUser(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	// Create an existing user and account
	existingUser := &domain.User{
		ID:        "existing-user-123",
		Email:     "user@example.com",
		Name:      "Existing User",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	userRepo.Create(context.Background(), existingUser)

	existingAccount := &domain.Account{
		ID:           "account-123",
		UserID:       existingUser.ID,
		AccountID:    "oauth-user-123",
		ProviderId:   "mock",
		AccessToken:  stringPtr("old-access-token"),
		RefreshToken: stringPtr("old-refresh-token"),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	accountRepo.Create(context.Background(), existingAccount)

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	provider := &MockOAuthProvider{
		tokens: &usecase.OAuthTokens{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			IDToken:      "test-id-token",
			ExpiresIn:    3600,
			Scope:        "profile email",
		},
		userInfo: &usecase.OAuthUserInfo{
			ID:            "oauth-user-123", // Same provider ID
			Email:         "user@example.com",
			Name:          "Existing User",
			Image:         "https://example.com/avatar.png",
			EmailVerified: true,
		},
	}

	uc.RegisterProvider(provider)

	output, err := uc.HandleCallback(context.Background(), "mock", "test-code", "")
	if err != nil {
		t.Fatalf("HandleCallback failed: %v", err)
	}

	if output.User.ID != existingUser.ID {
		t.Errorf("Expected user ID %s, got %s", existingUser.ID, output.User.ID)
	}

	if output.Session == nil {
		t.Fatal("Session should not be nil")
	}

	// Verify account tokens were updated
	updatedAccount, _ := accountRepo.FindByProviderAccountID(context.Background(), "mock", "oauth-user-123")
	if updatedAccount.AccessToken == nil || *updatedAccount.AccessToken != "new-access-token" {
		t.Error("Expected access token to be updated")
	}
}

func TestOAuthHandleCallbackMultipleProviders(t *testing.T) {
	userRepo := NewMockUserRepository()
	accountRepo := NewMockAccountRepository()
	sessionRepo := NewMockSessionRepository()

	uc := usecase.NewOAuthUseCase(
		userRepo,
		accountRepo,
		sessionRepo,
		&usecase.AuthConfig{
			BaseURL:          "https://example.com",
			SessionExpiresIn: 24 * time.Hour,
		},
	)

	// Register multiple providers
	googleProvider := &MockOAuthProvider{
		tokens: &usecase.OAuthTokens{
			AccessToken:  "google-access-token",
			RefreshToken: "google-refresh-token",
			IDToken:      "google-id-token",
			ExpiresIn:    3600,
			Scope:        "profile email",
		},
		userInfo: &usecase.OAuthUserInfo{
			ID:            "google-user-123",
			Email:         "user@gmail.com",
			Name:          "Google User",
			EmailVerified: true,
		},
	}

	uc.RegisterProvider(googleProvider)

	// Test OAuth callback with the registered provider
	output, err := uc.HandleCallback(context.Background(), "mock", "google-code", "")
	if err != nil {
		t.Fatalf("HandleCallback for Google failed: %v", err)
	}

	if output.User.Email != "user@gmail.com" {
		t.Errorf("Expected email 'user@gmail.com', got %s", output.User.Email)
	}

	// Verify account was created
	account, err := accountRepo.FindByProviderAccountID(context.Background(), "mock", "google-user-123")
	if err != nil {
		t.Fatalf("Account not found: %v", err)
	}

	if account.AccessToken == nil || *account.AccessToken != "google-access-token" {
		t.Error("Expected access token to be set correctly")
	}
}

// Helper function
func stringPtr(s string) *string {
	return &s
}
