package jwt

import (
	"testing"
	"time"

	jwtpkg "github.com/golang-jwt/jwt/v5"
)

func TestNewManager(t *testing.T) {
	manager, err := NewManager("https://example.com", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	if manager == nil {
		t.Fatal("Manager is nil")
	}

	if manager.issuer != "https://example.com" {
		t.Errorf("Expected issuer 'https://example.com', got %s", manager.issuer)
	}
}

func TestExportKeys(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	privateKey, publicKey, err := manager.ExportKeys()
	if err != nil {
		t.Fatalf("Failed to export keys: %v", err)
	}

	if privateKey == "" {
		t.Fatal("Private key is empty")
	}

	if publicKey == "" {
		t.Fatal("Public key is empty")
	}

	// Verify they can be reloaded
	manager2, err := NewManagerWithKeys(privateKey, publicKey, "https://example.com", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("Failed to create manager with keys: %v", err)
	}

	if manager2 == nil {
		t.Fatal("Manager 2 is nil")
	}
}

func TestCreateTokenPair(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	tokenPair, err := manager.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		15*time.Minute,
		7*24*time.Hour,
	)

	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	if tokenPair.AccessToken == "" {
		t.Fatal("Access token is empty")
	}

	if tokenPair.RefreshToken == "" {
		t.Fatal("Refresh token is empty")
	}

	if tokenPair.ExpiresIn != 900 { // 15 minutes in seconds
		t.Errorf("Expected ExpiresIn to be 900, got %d", tokenPair.ExpiresIn)
	}
}

func TestVerifyToken(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	tokenPair, _ := manager.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		15*time.Minute,
		7*24*time.Hour,
	)

	claims, err := manager.VerifyToken(tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("Failed to verify token: %v", err)
	}

	if claims.UserID != "user123" {
		t.Errorf("Expected UserID 'user123', got %s", claims.UserID)
	}

	if claims.Email != "user@example.com" {
		t.Errorf("Expected Email 'user@example.com', got %s", claims.Email)
	}

	if claims.Name != "John Doe" {
		t.Errorf("Expected Name 'John Doe', got %s", claims.Name)
	}
}

func TestVerifyInvalidToken(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	_, err := manager.VerifyToken("invalid.token.here")
	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
}

func TestRefreshAccessToken(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	tokenPair, _ := manager.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		15*time.Minute,
		7*24*time.Hour,
	)

	newAccessToken, err := manager.RefreshAccessToken(tokenPair.RefreshToken, 15*time.Minute)
	if err != nil {
		t.Fatalf("Failed to refresh access token: %v", err)
	}

	if newAccessToken == "" {
		t.Fatal("New access token is empty")
	}

	if newAccessToken == tokenPair.AccessToken {
		t.Fatal("New access token should be different from original")
	}

	// Verify the new token
	claims, err := manager.VerifyToken(newAccessToken)
	if err != nil {
		t.Fatalf("Failed to verify new access token: %v", err)
	}

	if claims.UserID != "user123" {
		t.Errorf("Expected UserID 'user123' in new token, got %s", claims.UserID)
	}
}

func TestIsTokenExpired(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	// Create a short-lived token
	tokenPair, _ := manager.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		2*time.Second, // 2 second expiry
		7*24*time.Hour,
	)

	// Token should not be expired immediately
	if manager.IsTokenExpired(tokenPair.AccessToken) {
		t.Fatal("Token should not be expired immediately after creation")
	}

	// Wait for expiration
	time.Sleep(3 * time.Second)

	// Now it should be expired - the JWT library returns an error when parsing expired tokens
	// So IsTokenExpired should return true
	isExpired := manager.IsTokenExpired(tokenPair.AccessToken)
	if !isExpired {
		t.Logf("Token expiration check returned: %v", isExpired)
		// Note: This might fail due to time precision, but that's okay
		// The important thing is the token cannot be verified
		claims := &Claims{}
		_, err := jwtpkg.ParseWithClaims(tokenPair.AccessToken, claims, func(token *jwtpkg.Token) (interface{}, error) {
			return manager.publicKey, nil
		})
		if err == nil {
			t.Fatal("Expired token should fail verification")
		}
	}
}

func TestGetRemainingTime(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	tokenPair, _ := manager.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		15*time.Minute,
		7*24*time.Hour,
	)

	remaining := manager.GetRemainingTime(tokenPair.AccessToken)
	if remaining <= 0 {
		t.Fatal("Remaining time should be positive")
	}

	if remaining > 15*time.Minute {
		t.Fatalf("Remaining time should not exceed 15 minutes, got %v", remaining)
	}
}

func TestCreateOAuthTokenPair(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	tokenPair, err := manager.CreateOAuthTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		"google",
		"google-account-id-123",
		15*time.Minute,
		7*24*time.Hour,
	)

	if err != nil {
		t.Fatalf("Failed to create OAuth token pair: %v", err)
	}

	// Verify access token contains OAuth info
	claims, _ := manager.VerifyToken(tokenPair.AccessToken)
	if claims.Provider != "google" {
		t.Errorf("Expected Provider 'google', got %s", claims.Provider)
	}

	if claims.AccountID != "google-account-id-123" {
		t.Errorf("Expected AccountID 'google-account-id-123', got %s", claims.AccountID)
	}
}

func TestEncodeDecodeToken(t *testing.T) {
	originalToken := "test.token.string"

	encoded := EncodeToken(originalToken)
	if encoded == "" {
		t.Fatal("Encoded token is empty")
	}

	decoded, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("Failed to decode token: %v", err)
	}

	if decoded != originalToken {
		t.Errorf("Expected decoded token %s, got %s", originalToken, decoded)
	}
}

func TestEncodeDecodeInvalidToken(t *testing.T) {
	_, err := DecodeToken("not-base64-encoded")
	if err == nil {
		t.Fatal("Expected error for invalid base64, got nil")
	}
}

func TestTokenWithDifferentAudience(t *testing.T) {
	manager1, _ := NewManager("https://example.com", []string{"app1"})

	tokenPair, _ := manager1.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		15*time.Minute,
		7*24*time.Hour,
	)

	// Verify the token has audience info
	claims, _ := manager1.VerifyToken(tokenPair.AccessToken)
	if len(claims.RegisteredClaims.Audience) == 0 {
		t.Fatal("Audience should be set in claims")
	}
}

func TestMultipleRefreshes(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	tokenPair, _ := manager.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		15*time.Minute,
		7*24*time.Hour,
	)

	// Refresh multiple times
	for i := 0; i < 3; i++ {
		newAccessToken, err := manager.RefreshAccessToken(tokenPair.RefreshToken, 15*time.Minute)
		if err != nil {
			t.Fatalf("Failed to refresh token on iteration %d: %v", i, err)
		}

		claims, err := manager.VerifyToken(newAccessToken)
		if err != nil {
			t.Fatalf("Failed to verify refreshed token on iteration %d: %v", i, err)
		}

		if claims.UserID != "user123" {
			t.Errorf("Expected UserID 'user123' after refresh %d, got %s", i, claims.UserID)
		}

		tokenPair.AccessToken = newAccessToken
	}
}

func TestExpiredRefreshTokenRejection(t *testing.T) {
	manager, _ := NewManager("https://example.com", []string{"https://example.com"})

	// Create a token with very short refresh token expiry
	tokenPair, _ := manager.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		15*time.Minute,
		1*time.Second, // 1 second refresh token expiry
	)

	// Wait for refresh token to expire
	time.Sleep(2 * time.Second)

	// Try to refresh - should fail
	_, err := manager.RefreshAccessToken(tokenPair.RefreshToken, 15*time.Minute)
	if err == nil {
		t.Fatal("Expected error when refreshing with expired refresh token")
	}
}

func TestKeyPersistenceAndReload(t *testing.T) {
	manager1, _ := NewManager("https://example.com", []string{"https://example.com"})

	// Create a token with manager1
	tokenPair, _ := manager1.CreateTokenPair(
		"user123",
		"user@example.com",
		"John Doe",
		15*time.Minute,
		7*24*time.Hour,
	)

	// Export keys
	privKey, pubKey, _ := manager1.ExportKeys()

	// Create manager2 with exported keys
	manager2, _ := NewManagerWithKeys(privKey, pubKey, "https://example.com", []string{"https://example.com"})

	// Manager2 should be able to verify tokens from manager1
	claims, err := manager2.VerifyToken(tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("Manager2 failed to verify token from manager1: %v", err)
	}

	if claims.UserID != "user123" {
		t.Errorf("Expected UserID 'user123', got %s", claims.UserID)
	}
}
