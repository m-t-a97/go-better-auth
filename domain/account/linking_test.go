package account

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test LinkingRules

func TestDefaultLinkingRules(t *testing.T) {
	rules := DefaultLinkingRules()

	assert.True(t, rules.AllowMultipleProvidersPerUser)
	assert.True(t, rules.AllowCredentialAndSocialMix)
	assert.False(t, rules.RequireEmailVerificationBeforeLinking)
}

// Test ValidateLinkAccountRequest

func TestValidateLinkAccountRequest_Valid_Credential(t *testing.T) {
	password := "hashed-password"
	req := &LinkAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderCredential,
		AccountID:  "email@example.com",
		Password:   &password,
	}

	err := ValidateLinkAccountRequest(req, DefaultLinkingRules())
	assert.NoError(t, err)
}

func TestValidateLinkAccountRequest_Valid_Google(t *testing.T) {
	token := "access-token-123"
	req := &LinkAccountRequest{
		UserID:      "user-123",
		ProviderID:  ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: &token,
	}

	err := ValidateLinkAccountRequest(req, DefaultLinkingRules())
	assert.NoError(t, err)
}

func TestValidateLinkAccountRequest_Nil(t *testing.T) {
	err := ValidateLinkAccountRequest(nil, DefaultLinkingRules())
	assert.Error(t, err)
	assert.Equal(t, "request cannot be nil", err.Error())
}

func TestValidateLinkAccountRequest_NoUserID(t *testing.T) {
	password := "password"
	req := &LinkAccountRequest{
		UserID:     "",
		ProviderID: ProviderCredential,
		AccountID:  "email@example.com",
		Password:   &password,
	}

	err := ValidateLinkAccountRequest(req, DefaultLinkingRules())
	assert.Error(t, err)
	assert.Equal(t, "user_id cannot be empty", err.Error())
}

func TestValidateLinkAccountRequest_NoProviderID(t *testing.T) {
	password := "password"
	req := &LinkAccountRequest{
		UserID:     "user-123",
		ProviderID: "",
		AccountID:  "email@example.com",
		Password:   &password,
	}

	err := ValidateLinkAccountRequest(req, DefaultLinkingRules())
	assert.Error(t, err)
	assert.Equal(t, "provider_id cannot be empty", err.Error())
}

func TestValidateLinkAccountRequest_InvalidProvider(t *testing.T) {
	password := "password"
	req := &LinkAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderType("invalid-provider"),
		AccountID:  "email@example.com",
		Password:   &password,
	}

	err := ValidateLinkAccountRequest(req, DefaultLinkingRules())
	assert.Error(t, err)

	linkErr, ok := err.(LinkingError)
	assert.True(t, ok)
	assert.Equal(t, ErrCodeInvalidProvider, linkErr.Code)
}

func TestValidateLinkAccountRequest_NoAccountID(t *testing.T) {
	password := "password"
	req := &LinkAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderCredential,
		AccountID:  "",
		Password:   &password,
	}

	err := ValidateLinkAccountRequest(req, DefaultLinkingRules())
	assert.Error(t, err)
	assert.Equal(t, "account_id cannot be empty", err.Error())
}

func TestValidateLinkAccountRequest_Credential_NoPassword(t *testing.T) {
	req := &LinkAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderCredential,
		AccountID:  "email@example.com",
		Password:   nil,
	}

	err := ValidateLinkAccountRequest(req, DefaultLinkingRules())
	assert.Error(t, err)
	assert.Equal(t, "password is required for credential provider", err.Error())
}

func TestValidateLinkAccountRequest_OAuth_NoAccessToken(t *testing.T) {
	req := &LinkAccountRequest{
		UserID:      "user-123",
		ProviderID:  ProviderGoogle,
		AccountID:   "google-user-456",
		AccessToken: nil,
	}

	err := ValidateLinkAccountRequest(req, DefaultLinkingRules())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_token is required")
}

// Test ValidateUnlinkAccountRequest

func TestValidateUnlinkAccountRequest_Valid(t *testing.T) {
	req := &UnlinkAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderGoogle,
	}

	err := ValidateUnlinkAccountRequest(req)
	assert.NoError(t, err)
}

func TestValidateUnlinkAccountRequest_Nil(t *testing.T) {
	err := ValidateUnlinkAccountRequest(nil)
	assert.Error(t, err)
	assert.Equal(t, "request cannot be nil", err.Error())
}

func TestValidateUnlinkAccountRequest_NoUserID(t *testing.T) {
	req := &UnlinkAccountRequest{
		UserID:     "",
		ProviderID: ProviderGoogle,
	}

	err := ValidateUnlinkAccountRequest(req)
	assert.Error(t, err)
	assert.Equal(t, "user_id cannot be empty", err.Error())
}

func TestValidateUnlinkAccountRequest_InvalidProvider(t *testing.T) {
	req := &UnlinkAccountRequest{
		UserID:     "user-123",
		ProviderID: ProviderType("invalid"),
	}

	err := ValidateUnlinkAccountRequest(req)
	assert.Error(t, err)

	linkErr, ok := err.(LinkingError)
	assert.True(t, ok)
	assert.Equal(t, ErrCodeInvalidProvider, linkErr.Code)
}

// Test CanLinkProvider

func TestCanLinkProvider_NoExistingAccounts(t *testing.T) {
	rules := DefaultLinkingRules()

	canLink, linkErr := CanLinkProvider([]*Account{}, ProviderGoogle, rules)

	assert.True(t, canLink)
	assert.Equal(t, "", linkErr.Code)
}

func TestCanLinkProvider_DuplicateProvider(t *testing.T) {
	rules := DefaultLinkingRules()
	token := "access-token"
	existingAccounts := []*Account{
		{
			ID:          "acc-1",
			UserID:      "user-123",
			AccountID:   "google-user-456",
			ProviderID:  ProviderGoogle,
			AccessToken: &token,
		},
	}

	canLink, linkErr := CanLinkProvider(existingAccounts, ProviderGoogle, rules)

	assert.False(t, canLink)
	assert.Equal(t, ErrCodeDuplicateProvider, linkErr.Code)
}

func TestCanLinkProvider_DifferentProvidersAllowed(t *testing.T) {
	rules := DefaultLinkingRules()
	token := "access-token"
	existingAccounts := []*Account{
		{
			ID:          "acc-1",
			UserID:      "user-123",
			AccountID:   "google-user-456",
			ProviderID:  ProviderGoogle,
			AccessToken: &token,
		},
	}

	canLink, linkErr := CanLinkProvider(existingAccounts, ProviderGitHub, rules)

	assert.True(t, canLink)
	assert.Equal(t, "", linkErr.Code)
}

func TestCanLinkProvider_CredentialAndSocialMix_NotAllowed(t *testing.T) {
	rules := DefaultLinkingRules()
	rules.AllowCredentialAndSocialMix = false

	password := "hashed-password"
	existingAccounts := []*Account{
		{
			ID:         "acc-1",
			UserID:     "user-123",
			AccountID:  "email@example.com",
			ProviderID: ProviderCredential,
			Password:   &password,
		},
	}

	canLink, linkErr := CanLinkProvider(existingAccounts, ProviderGoogle, rules)

	assert.False(t, canLink)
	assert.Equal(t, ErrCodeCannotMixCredentialWithSocial, linkErr.Code)
}

func TestCanLinkProvider_SocialThenCredential_NotAllowed(t *testing.T) {
	rules := DefaultLinkingRules()
	rules.AllowCredentialAndSocialMix = false

	token := "access-token"
	existingAccounts := []*Account{
		{
			ID:          "acc-1",
			UserID:      "user-123",
			AccountID:   "google-user-456",
			ProviderID:  ProviderGoogle,
			AccessToken: &token,
		},
	}

	canLink, linkErr := CanLinkProvider(existingAccounts, ProviderCredential, rules)

	assert.False(t, canLink)
	assert.Equal(t, ErrCodeCannotMixCredentialWithSocial, linkErr.Code)
}

func TestCanLinkProvider_CredentialAndSocialMix_Allowed(t *testing.T) {
	rules := DefaultLinkingRules()
	rules.AllowCredentialAndSocialMix = true

	password := "hashed-password"
	existingAccounts := []*Account{
		{
			ID:         "acc-1",
			UserID:     "user-123",
			AccountID:  "email@example.com",
			ProviderID: ProviderCredential,
			Password:   &password,
		},
	}

	canLink, linkErr := CanLinkProvider(existingAccounts, ProviderGoogle, rules)

	assert.True(t, canLink)
	assert.Equal(t, "", linkErr.Code)
}

// Test CanUnlinkProvider

func TestCanUnlinkProvider_NoExistingAccounts(t *testing.T) {
	canUnlink, linkErr := CanUnlinkProvider([]*Account{}, ProviderGoogle)

	assert.False(t, canUnlink)
	assert.Equal(t, ErrCodeUnlinkLastAccount, linkErr.Code)
}

func TestCanUnlinkProvider_AccountNotFound(t *testing.T) {
	token := "access-token"
	existingAccounts := []*Account{
		{
			ID:          "acc-1",
			UserID:      "user-123",
			AccountID:   "google-user-456",
			ProviderID:  ProviderGoogle,
			AccessToken: &token,
		},
	}

	canUnlink, linkErr := CanUnlinkProvider(existingAccounts, ProviderGitHub)

	assert.False(t, canUnlink)
	assert.Equal(t, "account_not_found", linkErr.Code)
}

func TestCanUnlinkProvider_Valid_MultipleAccounts(t *testing.T) {
	token := "access-token"
	password := "hashed-password"
	existingAccounts := []*Account{
		{
			ID:          "acc-1",
			UserID:      "user-123",
			AccountID:   "google-user-456",
			ProviderID:  ProviderGoogle,
			AccessToken: &token,
		},
		{
			ID:         "acc-2",
			UserID:     "user-123",
			AccountID:  "email@example.com",
			ProviderID: ProviderCredential,
			Password:   &password,
		},
	}

	canUnlink, linkErr := CanUnlinkProvider(existingAccounts, ProviderGoogle)

	assert.True(t, canUnlink)
	assert.Equal(t, "", linkErr.Code)
}

func TestCanUnlinkProvider_LastCredentialAccount(t *testing.T) {
	password := "hashed-password"
	existingAccounts := []*Account{
		{
			ID:         "acc-1",
			UserID:     "user-123",
			AccountID:  "email@example.com",
			ProviderID: ProviderCredential,
			Password:   &password,
		},
	}

	canUnlink, linkErr := CanUnlinkProvider(existingAccounts, ProviderCredential)

	assert.False(t, canUnlink)
	assert.Equal(t, ErrCodeUnlinkLastAccount, linkErr.Code)
}

// Test ValidateProviderConsistency

func TestValidateProviderConsistency_Nil(t *testing.T) {
	err := ValidateProviderConsistency(nil)
	assert.Error(t, err)
	assert.Equal(t, "account cannot be nil", err.Error())
}

func TestValidateProviderConsistency_Credential_Valid(t *testing.T) {
	password := "hashed-password"
	acc := &Account{
		ID:         "acc-1",
		UserID:     "user-123",
		AccountID:  "email@example.com",
		ProviderID: ProviderCredential,
		Password:   &password,
	}

	err := ValidateProviderConsistency(acc)
	assert.NoError(t, err)
}

func TestValidateProviderConsistency_Credential_NoPassword(t *testing.T) {
	acc := &Account{
		ID:         "acc-1",
		UserID:     "user-123",
		AccountID:  "email@example.com",
		ProviderID: ProviderCredential,
		Password:   nil,
	}

	err := ValidateProviderConsistency(acc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential provider requires a password")
}

func TestValidateProviderConsistency_OAuth_Valid(t *testing.T) {
	token := "access-token"
	acc := &Account{
		ID:          "acc-1",
		UserID:      "user-123",
		AccountID:   "google-user-456",
		ProviderID:  ProviderGoogle,
		AccessToken: &token,
	}

	err := ValidateProviderConsistency(acc)
	assert.NoError(t, err)
}

func TestValidateProviderConsistency_OAuth_NoAccessToken(t *testing.T) {
	acc := &Account{
		ID:          "acc-1",
		UserID:      "user-123",
		AccountID:   "google-user-456",
		ProviderID:  ProviderGoogle,
		AccessToken: nil,
	}

	err := ValidateProviderConsistency(acc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access token")
}

// Test GetProviderAccountIdentifier

func TestGetProviderAccountIdentifier_Nil(t *testing.T) {
	identifier := GetProviderAccountIdentifier(nil)
	assert.Equal(t, "", identifier)
}

func TestGetProviderAccountIdentifier_Credential(t *testing.T) {
	password := "hashed-password"
	acc := &Account{
		ID:         "acc-1",
		UserID:     "user-123",
		AccountID:  "email@example.com",
		ProviderID: ProviderCredential,
		Password:   &password,
	}

	identifier := GetProviderAccountIdentifier(acc)
	assert.Contains(t, identifier, "Credential Account")
	assert.Contains(t, identifier, "email@example.com")
}

func TestGetProviderAccountIdentifier_Google(t *testing.T) {
	token := "access-token"
	acc := &Account{
		ID:          "acc-1",
		UserID:      "user-123",
		AccountID:   "google-user-456",
		ProviderID:  ProviderGoogle,
		AccessToken: &token,
	}

	identifier := GetProviderAccountIdentifier(acc)
	assert.Contains(t, identifier, "Google Account")
	assert.Contains(t, identifier, "google-user-456")
}

func TestGetProviderAccountIdentifier_GitHub(t *testing.T) {
	token := "access-token"
	acc := &Account{
		ID:          "acc-1",
		UserID:      "user-123",
		AccountID:   "github-user-789",
		ProviderID:  ProviderGitHub,
		AccessToken: &token,
	}

	identifier := GetProviderAccountIdentifier(acc)
	assert.Contains(t, identifier, "GitHub Account")
	assert.Contains(t, identifier, "github-user-789")
}

func TestGetProviderAccountIdentifier_Discord(t *testing.T) {
	token := "access-token"
	acc := &Account{
		ID:          "acc-1",
		UserID:      "user-123",
		AccountID:   "discord-user-999",
		ProviderID:  ProviderDiscord,
		AccessToken: &token,
	}

	identifier := GetProviderAccountIdentifier(acc)
	assert.Contains(t, identifier, "Discord Account")
	assert.Contains(t, identifier, "discord-user-999")
}

// Test ShouldRefreshAccessToken

func TestShouldRefreshAccessToken_Nil(t *testing.T) {
	shouldRefresh := ShouldRefreshAccessToken(nil, 5)
	assert.False(t, shouldRefresh)
}

func TestShouldRefreshAccessToken_Credential(t *testing.T) {
	password := "hashed-password"
	acc := &Account{
		ID:         "acc-1",
		UserID:     "user-123",
		AccountID:  "email@example.com",
		ProviderID: ProviderCredential,
		Password:   &password,
	}

	shouldRefresh := ShouldRefreshAccessToken(acc, 5)
	assert.False(t, shouldRefresh)
}

func TestShouldRefreshAccessToken_NoExpiryTime(t *testing.T) {
	token := "access-token"
	acc := &Account{
		ID:                   "acc-1",
		UserID:               "user-123",
		AccountID:            "google-user-456",
		ProviderID:           ProviderGoogle,
		AccessToken:          &token,
		AccessTokenExpiresAt: nil,
	}

	shouldRefresh := ShouldRefreshAccessToken(acc, 5)
	assert.False(t, shouldRefresh)
}

func TestShouldRefreshAccessToken_NoRefreshToken(t *testing.T) {
	token := "access-token"
	expiryTime := time.Now().Add(2 * time.Minute)
	acc := &Account{
		ID:                   "acc-1",
		UserID:               "user-123",
		AccountID:            "google-user-456",
		ProviderID:           ProviderGoogle,
		AccessToken:          &token,
		AccessTokenExpiresAt: &expiryTime,
		RefreshToken:         nil,
	}

	shouldRefresh := ShouldRefreshAccessToken(acc, 5)
	assert.False(t, shouldRefresh)
}

func TestShouldRefreshAccessToken_TokenExpiringSoon(t *testing.T) {
	token := "access-token"
	refreshToken := "refresh-token"
	expiryTime := time.Now().Add(2 * time.Minute)
	acc := &Account{
		ID:                   "acc-1",
		UserID:               "user-123",
		AccountID:            "google-user-456",
		ProviderID:           ProviderGoogle,
		AccessToken:          &token,
		AccessTokenExpiresAt: &expiryTime,
		RefreshToken:         &refreshToken,
	}

	shouldRefresh := ShouldRefreshAccessToken(acc, 5)
	assert.True(t, shouldRefresh)
}

func TestShouldRefreshAccessToken_TokenNotExpiringSoon(t *testing.T) {
	token := "access-token"
	refreshToken := "refresh-token"
	expiryTime := time.Now().Add(1 * time.Hour)
	acc := &Account{
		ID:                   "acc-1",
		UserID:               "user-123",
		AccountID:            "google-user-456",
		ProviderID:           ProviderGoogle,
		AccessToken:          &token,
		AccessTokenExpiresAt: &expiryTime,
		RefreshToken:         &refreshToken,
	}

	shouldRefresh := ShouldRefreshAccessToken(acc, 5)
	assert.False(t, shouldRefresh)
}

func TestShouldRefreshAccessToken_TokenAlreadyExpired(t *testing.T) {
	token := "access-token"
	refreshToken := "refresh-token"
	expiryTime := time.Now().Add(-10 * time.Minute)
	acc := &Account{
		ID:                   "acc-1",
		UserID:               "user-123",
		AccountID:            "google-user-456",
		ProviderID:           ProviderGoogle,
		AccessToken:          &token,
		AccessTokenExpiresAt: &expiryTime,
		RefreshToken:         &refreshToken,
	}

	shouldRefresh := ShouldRefreshAccessToken(acc, 5)
	assert.True(t, shouldRefresh)
}

// Integration tests

func TestAccountLinkingScenarios(t *testing.T) {
	t.Run("Link first account", func(t *testing.T) {
		rules := DefaultLinkingRules()
		password := "hashed-password"

		// First account (credential)
		canLink, err := CanLinkProvider([]*Account{}, ProviderCredential, rules)
		require.True(t, canLink)
		require.Equal(t, "", err.Code)

		// Validate request
		req := &LinkAccountRequest{
			UserID:     "user-123",
			ProviderID: ProviderCredential,
			AccountID:  "email@example.com",
			Password:   &password,
		}
		validErr := ValidateLinkAccountRequest(req, rules)
		require.NoError(t, validErr)
	})

	t.Run("Link second account from different provider", func(t *testing.T) {
		rules := DefaultLinkingRules()
		password := "hashed-password"
		token := "access-token"

		existingAccounts := []*Account{
			{
				ID:         "acc-1",
				UserID:     "user-123",
				AccountID:  "email@example.com",
				ProviderID: ProviderCredential,
				Password:   &password,
			},
		}

		// Try to link Google
		canLink, err := CanLinkProvider(existingAccounts, ProviderGoogle, rules)
		require.True(t, canLink)
		require.Equal(t, "", err.Code)

		// Validate request
		req := &LinkAccountRequest{
			UserID:      "user-123",
			ProviderID:  ProviderGoogle,
			AccountID:   "google-user-456",
			AccessToken: &token,
		}
		validErr := ValidateLinkAccountRequest(req, rules)
		require.NoError(t, validErr)
	})

	t.Run("Cannot link duplicate provider", func(t *testing.T) {
		rules := DefaultLinkingRules()
		token := "access-token"

		existingAccounts := []*Account{
			{
				ID:          "acc-1",
				UserID:      "user-123",
				AccountID:   "google-user-456",
				ProviderID:  ProviderGoogle,
				AccessToken: &token,
			},
		}

		// Try to link Google again
		canLink, err := CanLinkProvider(existingAccounts, ProviderGoogle, rules)
		require.False(t, canLink)
		require.Equal(t, ErrCodeDuplicateProvider, err.Code)
	})

	t.Run("Unlink with multiple accounts", func(t *testing.T) {
		password := "hashed-password"
		token := "access-token"

		existingAccounts := []*Account{
			{
				ID:          "acc-1",
				UserID:      "user-123",
				AccountID:   "google-user-456",
				ProviderID:  ProviderGoogle,
				AccessToken: &token,
			},
			{
				ID:         "acc-2",
				UserID:     "user-123",
				AccountID:  "email@example.com",
				ProviderID: ProviderCredential,
				Password:   &password,
			},
		}

		// Can unlink Google
		canUnlink, err := CanUnlinkProvider(existingAccounts, ProviderGoogle)
		require.True(t, canUnlink)
		require.Equal(t, "", err.Code)

		// Can unlink credential since we have another account
		canUnlink, err = CanUnlinkProvider(existingAccounts, ProviderCredential)
		require.True(t, canUnlink)
		require.Equal(t, "", err.Code)
	})

	t.Run("Cannot unlink last credential account", func(t *testing.T) {
		password := "hashed-password"

		existingAccounts := []*Account{
			{
				ID:         "acc-1",
				UserID:     "user-123",
				AccountID:  "email@example.com",
				ProviderID: ProviderCredential,
				Password:   &password,
			},
		}

		canUnlink, err := CanUnlinkProvider(existingAccounts, ProviderCredential)
		require.False(t, canUnlink)
		require.Equal(t, ErrCodeUnlinkLastAccount, err.Code)
	})
}
