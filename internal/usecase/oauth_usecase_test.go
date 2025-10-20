package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/internal/usecase"
)

// Mock OAuth Provider for testing
type MockOAuthProvider struct {
	tokens   *usecase.OAuthTokens
	userInfo *usecase.OAuthUserInfo
}

func (m *MockOAuthProvider) GetProviderID() string {
	return "mock"
}

func (m *MockOAuthProvider) GetAuthURL(state, redirectURI string) string {
	return "https://mock-provider.com/auth?state=" + state
}

func (m *MockOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*usecase.OAuthTokens, error) {
	return m.tokens, nil
}

func (m *MockOAuthProvider) GetUserInfo(ctx context.Context, accessToken string) (*usecase.OAuthUserInfo, error) {
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

// Helper function
func stringPtr(s string) *string {
	return &s
}
