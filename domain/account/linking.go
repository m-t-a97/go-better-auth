package account

import (
	"fmt"
	"time"
)

// LinkingRules defines the business rules for account linking
type LinkingRules struct {
	// AllowMultipleProvidersPerUser specifies if a user can link multiple accounts from different providers
	AllowMultipleProvidersPerUser bool
	// AllowCredentialAndSocialMix specifies if credential (email/password) can be linked with social providers
	AllowCredentialAndSocialMix bool
	// RequireEmailVerificationBeforeLinking specifies if email must be verified before linking accounts
	RequireEmailVerificationBeforeLinking bool
}

// DefaultLinkingRules returns the default account linking rules
func DefaultLinkingRules() LinkingRules {
	return LinkingRules{
		AllowMultipleProvidersPerUser:         true,
		AllowCredentialAndSocialMix:           true,
		RequireEmailVerificationBeforeLinking: false,
	}
}

// LinkAccountRequest represents a request to link an account to an existing user
type LinkAccountRequest struct {
	UserID                string       // The user to link the account to
	ProviderID            ProviderType // The provider of the account to link
	AccountID             string       // Provider-specific account ID
	AccessToken           *string
	RefreshToken          *string
	IDToken               *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string
	Password              *string // For credential provider only
}

// UnlinkAccountRequest represents a request to unlink an account from a user
type UnlinkAccountRequest struct {
	UserID     string       // The user to unlink the account from
	ProviderID ProviderType // The provider of the account to unlink
}

// LinkingError represents an error that occurs during account linking operations
type LinkingError struct {
	Code    string // Error code for programmatic handling
	Message string // Human-readable error message
}

func (e LinkingError) Error() string {
	return e.Message
}

// Error codes for account linking
const (
	ErrCodeDuplicateProvider             = "duplicate_provider"
	ErrCodeCannotMixCredentialWithSocial = "cannot_mix_credential_with_social"
	ErrCodeOnlyOneAccountAllowed         = "only_one_account_allowed"
	ErrCodeInvalidProvider               = "invalid_provider"
	ErrCodeAccountAlreadyLinked          = "account_already_linked"
	ErrCodeEmailMismatch                 = "email_mismatch"
	ErrCodeEmailNotVerified              = "email_not_verified"
	ErrCodeUnlinkLastAccount             = "cannot_unlink_last_account"
)

// ValidateLinkAccountRequest validates a link account request according to business rules
func ValidateLinkAccountRequest(req *LinkAccountRequest, rules LinkingRules) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.UserID == "" {
		return fmt.Errorf("user_id cannot be empty")
	}

	if req.ProviderID == "" {
		return fmt.Errorf("provider_id cannot be empty")
	}

	if !isValidProvider(req.ProviderID) {
		return LinkingError{
			Code:    ErrCodeInvalidProvider,
			Message: fmt.Sprintf("invalid provider: %s", req.ProviderID),
		}
	}

	if req.AccountID == "" {
		return fmt.Errorf("account_id cannot be empty")
	}

	// Credential provider requires password
	if req.ProviderID == ProviderCredential {
		if req.Password == nil || *req.Password == "" {
			return fmt.Errorf("password is required for credential provider")
		}
	} else {
		// OAuth providers require access token
		if req.AccessToken == nil || *req.AccessToken == "" {
			return fmt.Errorf("access_token is required for %s provider", req.ProviderID)
		}
	}

	return nil
}

// ValidateUnlinkAccountRequest validates an unlink account request
func ValidateUnlinkAccountRequest(req *UnlinkAccountRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.UserID == "" {
		return fmt.Errorf("user_id cannot be empty")
	}

	if req.ProviderID == "" {
		return fmt.Errorf("provider_id cannot be empty")
	}

	if !isValidProvider(req.ProviderID) {
		return LinkingError{
			Code:    ErrCodeInvalidProvider,
			Message: fmt.Sprintf("invalid provider: %s", req.ProviderID),
		}
	}

	return nil
}

// CanLinkProvider checks if a provider can be linked based on existing accounts and rules
func CanLinkProvider(existingAccounts []*Account, newProviderID ProviderType, rules LinkingRules) (bool, LinkingError) {
	if len(existingAccounts) == 0 {
		// No existing accounts, can always link
		return true, LinkingError{}
	}

	// Check if provider is already linked
	for _, acc := range existingAccounts {
		if acc.ProviderID == newProviderID {
			return false, LinkingError{
				Code:    ErrCodeDuplicateProvider,
				Message: fmt.Sprintf("account with provider %s is already linked", newProviderID),
			}
		}
	}

	// If mix of credential and social is not allowed, check for compatibility
	if !rules.AllowCredentialAndSocialMix {
		hasCredential := false
		hasSocial := false

		for _, acc := range existingAccounts {
			if acc.ProviderID == ProviderCredential {
				hasCredential = true
			} else {
				hasSocial = true
			}
		}

		isNewCredential := newProviderID == ProviderCredential
		isNewSocial := newProviderID != ProviderCredential

		if (hasCredential && isNewSocial) || (hasSocial && isNewCredential) {
			return false, LinkingError{
				Code:    ErrCodeCannotMixCredentialWithSocial,
				Message: "cannot link credential and social providers together",
			}
		}
	}

	return true, LinkingError{}
}

// CanUnlinkProvider checks if a provider can be unlinked based on existing accounts
func CanUnlinkProvider(existingAccounts []*Account, providerIDToUnlink ProviderType) (bool, LinkingError) {
	if len(existingAccounts) == 0 {
		return false, LinkingError{
			Code:    ErrCodeUnlinkLastAccount,
			Message: "cannot unlink: no accounts available to unlink",
		}
	}

	// Check if the account exists
	found := false
	for _, acc := range existingAccounts {
		if acc.ProviderID == providerIDToUnlink {
			found = true
			break
		}
	}

	if !found {
		return false, LinkingError{
			Code:    "account_not_found",
			Message: fmt.Sprintf("account with provider %s not found", providerIDToUnlink),
		}
	}

	// Prevent unlinking the last credential account (if only one account exists)
	if len(existingAccounts) == 1 && existingAccounts[0].ProviderID == ProviderCredential {
		return false, LinkingError{
			Code:    ErrCodeUnlinkLastAccount,
			Message: "cannot unlink the last account",
		}
	}

	return true, LinkingError{}
}

// ValidateProviderConsistency checks if provider data is consistent
func ValidateProviderConsistency(account *Account) error {
	if account == nil {
		return fmt.Errorf("account cannot be nil")
	}

	// Credential provider must have password
	if account.ProviderID == ProviderCredential {
		if account.Password == nil || *account.Password == "" {
			return fmt.Errorf("credential provider requires a password")
		}
	} else {
		// Social providers must have access token
		if account.AccessToken == nil || *account.AccessToken == "" {
			return fmt.Errorf("provider %s requires an access token", account.ProviderID)
		}
	}

	return nil
}

// GetProviderAccountIdentifier returns a human-readable identifier for a provider account
func GetProviderAccountIdentifier(account *Account) string {
	if account == nil {
		return ""
	}

	switch account.ProviderID {
	case ProviderCredential:
		return fmt.Sprintf("Credential Account (ID: %s)", account.AccountID)
	case ProviderGoogle:
		return fmt.Sprintf("Google Account (ID: %s)", account.AccountID)
	case ProviderGitHub:
		return fmt.Sprintf("GitHub Account (ID: %s)", account.AccountID)
	case ProviderDiscord:
		return fmt.Sprintf("Discord Account (ID: %s)", account.AccountID)
	case ProviderGeneric:
		return fmt.Sprintf("OAuth2 Account (ID: %s)", account.AccountID)
	default:
		return fmt.Sprintf("%s Account (ID: %s)", account.ProviderID, account.AccountID)
	}
}

// ShouldRefreshAccessToken checks if an access token should be refreshed
func ShouldRefreshAccessToken(account *Account, refreshThresholdMinutes int) bool {
	if account == nil {
		return false
	}

	// Credential provider doesn't need token refresh
	if account.ProviderID == ProviderCredential {
		return false
	}

	// If no expiry time is set, token doesn't expire
	if account.AccessTokenExpiresAt == nil {
		return false
	}

	// If no refresh token, cannot refresh
	if account.RefreshToken == nil || *account.RefreshToken == "" {
		return false
	}

	// Check if token will expire within threshold
	expiryTime := *account.AccessTokenExpiresAt
	thresholdTime := time.Now().Add(time.Duration(refreshThresholdMinutes) * time.Minute)

	return expiryTime.Before(thresholdTime)
}
