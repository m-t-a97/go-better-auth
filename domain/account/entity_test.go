package account

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateCreateAccountRequest_CredentialValid(t *testing.T) {
	password := "hashed-password-123"
	req := &CreateAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderCredential,
		AccountID:  "user-123",
		Password:   &password,
	}

	err := ValidateCreateAccountRequest(req)
	assert.NoError(t, err)
}

func TestValidateCreateAccountRequest_OAuthValid(t *testing.T) {
	accessToken := "oauth-access-token-123"
	req := &CreateAccountRequest{
		UserID:      "user-123",
		ProviderID:  ProviderGoogle,
		AccountID:   "google-account-id",
		AccessToken: &accessToken,
	}

	err := ValidateCreateAccountRequest(req)
	assert.NoError(t, err)
}

func TestValidateCreateAccountRequest_Nil(t *testing.T) {
	err := ValidateCreateAccountRequest(nil)
	assert.Error(t, err)
}

func TestValidateCreateAccountRequest_EmptyUserID(t *testing.T) {
	password := "hashed-password"
	req := &CreateAccountRequest{
		UserID:     "",
		ProviderID: ProviderCredential,
		AccountID:  "user-123",
		Password:   &password,
	}

	err := ValidateCreateAccountRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateAccountRequest_EmptyProviderID(t *testing.T) {
	password := "hashed-password"
	req := &CreateAccountRequest{
		UserID:     "user-123",
		ProviderID: "",
		AccountID:  "user-123",
		Password:   &password,
	}

	err := ValidateCreateAccountRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateAccountRequest_InvalidProvider(t *testing.T) {
	password := "hashed-password"
	req := &CreateAccountRequest{
		UserID:     "user-123",
		ProviderID: "invalid-provider",
		AccountID:  "user-123",
		Password:   &password,
	}

	err := ValidateCreateAccountRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateAccountRequest_CredentialMissingPassword(t *testing.T) {
	req := &CreateAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderCredential,
		AccountID:  "user-123",
	}

	err := ValidateCreateAccountRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateAccountRequest_OAuthMissingAccessToken(t *testing.T) {
	req := &CreateAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderGoogle,
		AccountID:  "google-123",
	}

	err := ValidateCreateAccountRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateAccountRequest_AccessTokenTooLong(t *testing.T) {
	accessToken := string(make([]byte, 6000))
	req := &CreateAccountRequest{
		UserID:      "user-123",
		ProviderID:  ProviderGoogle,
		AccountID:   "google-123",
		AccessToken: &accessToken,
	}

	err := ValidateCreateAccountRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateAccountRequest_EmptyAccountID(t *testing.T) {
	password := "hashed-password"
	req := &CreateAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderCredential,
		AccountID:  "",
		Password:   &password,
	}

	err := ValidateCreateAccountRequest(req)
	assert.Error(t, err)
}

func TestValidateUpdateAccountRequest_Valid(t *testing.T) {
	accessToken := "new-access-token"
	req := &UpdateAccountRequest{
		AccessToken: &accessToken,
	}

	err := ValidateUpdateAccountRequest(req)
	assert.NoError(t, err)
}

func TestValidateUpdateAccountRequest_Nil(t *testing.T) {
	err := ValidateUpdateAccountRequest(nil)
	assert.Error(t, err)
}

func TestValidateUpdateAccountRequest_TokenTooLong(t *testing.T) {
	accessToken := string(make([]byte, 6000))
	req := &UpdateAccountRequest{
		AccessToken: &accessToken,
	}

	err := ValidateUpdateAccountRequest(req)
	assert.Error(t, err)
}

func TestAccount_IsTokenExpired_NotExpired(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	account := &Account{
		AccessTokenExpiresAt: &futureTime,
	}

	assert.False(t, account.IsTokenExpired())
}

func TestAccount_IsTokenExpired_Expired(t *testing.T) {
	pastTime := time.Now().Add(-1 * time.Hour)
	account := &Account{
		AccessTokenExpiresAt: &pastTime,
	}

	assert.True(t, account.IsTokenExpired())
}

func TestAccount_IsTokenExpired_NoExpiration(t *testing.T) {
	account := &Account{
		AccessTokenExpiresAt: nil,
	}

	assert.False(t, account.IsTokenExpired())
}

func TestAccount_IsRefreshTokenExpired_NotExpired(t *testing.T) {
	futureTime := time.Now().Add(7 * 24 * time.Hour)
	account := &Account{
		RefreshTokenExpiresAt: &futureTime,
	}

	assert.False(t, account.IsRefreshTokenExpired())
}

func TestAccount_IsRefreshTokenExpired_Expired(t *testing.T) {
	pastTime := time.Now().Add(-1 * time.Hour)
	account := &Account{
		RefreshTokenExpiresAt: &pastTime,
	}

	assert.True(t, account.IsRefreshTokenExpired())
}

func TestAccount_IsRefreshTokenExpired_NoExpiration(t *testing.T) {
	account := &Account{
		RefreshTokenExpiresAt: nil,
	}

	assert.False(t, account.IsRefreshTokenExpired())
}

func TestIsValidProvider_Valid(t *testing.T) {
	validProviders := []ProviderType{
		ProviderCredential,
		ProviderGoogle,
		ProviderGitHub,
		ProviderDiscord,
		ProviderGeneric,
	}

	for _, provider := range validProviders {
		assert.True(t, isValidProvider(provider))
	}
}

func TestIsValidProvider_Invalid(t *testing.T) {
	assert.False(t, isValidProvider("invalid"))
	assert.False(t, isValidProvider("twitter"))
}
