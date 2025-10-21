package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/user"
)

// SyncProviderDataRequest represents a request to sync user data from an OAuth provider
type SyncProviderDataRequest struct {
	UserID     string
	ProviderID account.ProviderType
	OAuthUser  *account.OAuthUser
	UpdateUser bool // Whether to update user profile fields
}

// SyncProviderDataResponse represents the response from syncing provider data
type SyncProviderDataResponse struct {
	User    *user.User       `json:"user"`
	Account *account.Account `json:"account"`
	Changes map[string]bool  `json:"changes"` // Track what was changed
}

// SyncProviderData syncs user profile data from an OAuth provider to the user record
func (s *Service) SyncProviderData(ctx context.Context, req *SyncProviderDataRequest) (*SyncProviderDataResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.UserID == "" {
		return nil, fmt.Errorf("user_id cannot be empty")
	}

	if req.ProviderID == "" {
		return nil, fmt.Errorf("provider_id cannot be empty")
	}

	if req.OAuthUser == nil {
		return nil, fmt.Errorf("oauth_user cannot be nil")
	}

	// Get the user
	userRecord, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if userRecord == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get the linked account
	linkedAccount, err := s.accountRepo.FindByUserIDAndProvider(req.UserID, req.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("linked account not found: %w", err)
	}

	if linkedAccount == nil {
		return nil, fmt.Errorf("linked account not found")
	}

	changes := make(map[string]bool)

	// Update user profile if requested
	if req.UpdateUser {
		// Update name if provided and different
		if req.OAuthUser.Name != "" && req.OAuthUser.Name != userRecord.Name {
			userRecord.Name = req.OAuthUser.Name
			changes["name"] = true
		}

		// Update image if provided and different
		if req.OAuthUser.Picture != nil && *req.OAuthUser.Picture != "" {
			currentImage := ""
			if userRecord.Image != nil {
				currentImage = *userRecord.Image
			}
			if *req.OAuthUser.Picture != currentImage {
				userRecord.Image = req.OAuthUser.Picture
				changes["image"] = true
			}
		}

		// Update email if provided and different (requires verification)
		if req.OAuthUser.Email != "" && req.OAuthUser.Email != userRecord.Email {
			// Don't update email directly for security reasons - would need email verification
			slog.DebugContext(
				ctx,
				"email change detected from provider but not applied (requires verification)",
				"user_id", req.UserID,
				"provider", req.ProviderID,
				"old_email", userRecord.Email,
				"new_email", req.OAuthUser.Email,
			)
		}

		// Only update if there were changes
		if len(changes) > 0 {
			userRecord.UpdatedAt = time.Now()
			err = s.userRepo.Update(userRecord)
			if err != nil {
				return nil, fmt.Errorf("failed to update user: %w", err)
			}
		}
	}

	// Update account metadata (raw provider data)
	if linkedAccount.AccountID != req.OAuthUser.ID {
		linkedAccount.AccountID = req.OAuthUser.ID
		changes["account_id"] = true
	}

	if len(changes) > 0 || len(changes) == 0 {
		// Always update the account's UpdatedAt timestamp
		linkedAccount.UpdatedAt = time.Now()
		err = s.accountRepo.Update(linkedAccount)
		if err != nil {
			return nil, fmt.Errorf("failed to update account: %w", err)
		}
		changes["account_updated"] = true
	}

	return &SyncProviderDataResponse{
		User:    userRecord,
		Account: linkedAccount,
		Changes: changes,
	}, nil
}

// SyncMultipleProvidersData syncs data from multiple linked OAuth providers
// Returns the latest successful update
func (s *Service) SyncMultipleProvidersData(ctx context.Context, userID string, providerData map[account.ProviderType]*account.OAuthUser) (*SyncProviderDataResponse, error) {
	if userID == "" {
		return nil, fmt.Errorf("user_id cannot be empty")
	}

	if len(providerData) == 0 {
		return nil, fmt.Errorf("provider_data cannot be empty")
	}

	var latestResponse *SyncProviderDataResponse
	var lastErr error

	// Sync data from each provider
	for providerID, oauthUser := range providerData {
		req := &SyncProviderDataRequest{
			UserID:     userID,
			ProviderID: providerID,
			OAuthUser:  oauthUser,
			UpdateUser: latestResponse == nil, // Only update user on first provider
		}

		resp, err := s.SyncProviderData(ctx, req)
		if err != nil {
			slog.WarnContext(
				ctx,
				"failed to sync provider data",
				"user_id", userID,
				"provider", providerID,
				"error", err,
			)
			lastErr = err
			continue
		}

		latestResponse = resp
	}

	if latestResponse == nil && lastErr != nil {
		return nil, fmt.Errorf("failed to sync any provider data: %w", lastErr)
	}

	return latestResponse, nil
}

// GetProviderUserEmail retrieves the email from a provider user profile
func GetProviderUserEmail(oauthUser *account.OAuthUser) string {
	if oauthUser == nil {
		return ""
	}
	return oauthUser.Email
}

// GetProviderUserName retrieves the name from a provider user profile
func GetProviderUserName(oauthUser *account.OAuthUser) string {
	if oauthUser == nil {
		return ""
	}
	return oauthUser.Name
}

// GetProviderUserPicture retrieves the picture URL from a provider user profile
func GetProviderUserPicture(oauthUser *account.OAuthUser) *string {
	if oauthUser == nil {
		return nil
	}
	return oauthUser.Picture
}

// MergeProviderProfiles merges multiple provider profiles, preferring non-empty fields
// Providers are processed in order, later providers override earlier ones only for empty fields
func MergeProviderProfiles(profiles ...*account.OAuthUser) *account.OAuthUser {
	if len(profiles) == 0 {
		return nil
	}

	merged := &account.OAuthUser{
		RawData: make(map[string]interface{}),
	}

	// Process profiles in order
	for _, profile := range profiles {
		if profile == nil {
			continue
		}

		// Take the first non-empty ID
		if merged.ID == "" && profile.ID != "" {
			merged.ID = profile.ID
		}

		// Take the first non-empty Email
		if merged.Email == "" && profile.Email != "" {
			merged.Email = profile.Email
		}

		// Take the first non-empty Name
		if merged.Name == "" && profile.Name != "" {
			merged.Name = profile.Name
		}

		// Take the first non-empty Picture
		if merged.Picture == nil && profile.Picture != nil {
			merged.Picture = profile.Picture
		}

		// Merge raw data (later entries override)
		if profile.RawData != nil {
			for k, v := range profile.RawData {
				merged.RawData[k] = v
			}
		}
	}

	return merged
}
