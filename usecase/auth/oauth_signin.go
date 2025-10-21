package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// OAuthSignInRequest represents a request to sign in via OAuth
type OAuthSignInRequest struct {
	ProviderID  account.ProviderType
	OAuthUser   *account.OAuthUser
	OAuthTokens *account.OAuthTokens
}

// OAuthSignInResponse represents the response from OAuth sign in
type OAuthSignInResponse struct {
	User      *user.User       `json:"user"`
	Session   *session.Session `json:"session"`
	Account   *account.Account `json:"account"`
	IsNewUser bool             `json:"is_new_user"`
}

// OAuthSignIn handles OAuth signin/signup flow
// It will:
// 1. Look up existing user by email from OAuth provider
// 2. If user exists, link the OAuth account if not already linked
// 3. If user doesn't exist, create a new user and link the OAuth account
// 4. Create a new session for the user
// 5. Sync user profile data from OAuth provider
func (s *Service) OAuthSignIn(ctx context.Context, req *OAuthSignInRequest) (*OAuthSignInResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.ProviderID == "" {
		return nil, fmt.Errorf("provider_id cannot be empty")
	}

	if req.OAuthUser == nil {
		return nil, fmt.Errorf("oauth_user cannot be nil")
	}

	if req.OAuthUser.Email == "" {
		return nil, fmt.Errorf("oauth user email cannot be empty")
	}

	if req.OAuthTokens == nil {
		return nil, fmt.Errorf("oauth_tokens cannot be nil")
	}

	// Try to find existing user by email
	existingUser, err := s.userRepo.FindByEmail(req.OAuthUser.Email)
	if err != nil && err.Error() != "user not found" {
		return nil, fmt.Errorf("failed to lookup user: %w", err)
	}

	var userRecord *user.User
	var isNewUser bool

	if existingUser == nil {
		// Create new user from OAuth profile
		userRecord, err = s.createUserFromOAuth(ctx, req.OAuthUser)
		if err != nil {
			return nil, fmt.Errorf("failed to create user from oauth: %w", err)
		}
		isNewUser = true

		slog.InfoContext(ctx, "created new user from oauth",
			"user_id", userRecord.ID,
			"email", userRecord.Email,
			"provider", req.ProviderID,
		)
	} else {
		userRecord = existingUser
		isNewUser = false

		slog.InfoContext(ctx, "found existing user for oauth signin",
			"user_id", userRecord.ID,
			"email", userRecord.Email,
			"provider", req.ProviderID,
		)
	}

	// Check if OAuth account is already linked
	existingAccount, err := s.accountRepo.FindByUserIDAndProvider(userRecord.ID, req.ProviderID)
	if err != nil && err.Error() != "account not found" {
		return nil, fmt.Errorf("failed to check existing account: %w", err)
	}

	var accountRecord *account.Account

	if existingAccount == nil {
		// Link the OAuth account
		accountRecord, err = s.linkOAuthAccountInternal(ctx, userRecord.ID, req.ProviderID, req.OAuthUser, req.OAuthTokens)
		if err != nil {
			return nil, fmt.Errorf("failed to link oauth account: %w", err)
		}

		slog.InfoContext(ctx, "linked oauth account to user",
			"user_id", userRecord.ID,
			"provider", req.ProviderID,
			"account_id", accountRecord.ID,
		)
	} else {
		// Update existing account with new tokens
		existingAccount.AccessToken = &req.OAuthTokens.AccessToken
		existingAccount.RefreshToken = req.OAuthTokens.RefreshToken
		existingAccount.IDToken = req.OAuthTokens.IDToken
		if req.OAuthTokens.AccessTokenExpiresAt != nil {
			existingAccount.AccessTokenExpiresAt = req.OAuthTokens.AccessTokenExpiresAt
		}
		existingAccount.Scope = &req.OAuthTokens.Scope
		existingAccount.UpdatedAt = time.Now()

		err = s.accountRepo.Update(existingAccount)
		if err != nil {
			return nil, fmt.Errorf("failed to update account tokens: %w", err)
		}

		accountRecord = existingAccount

		slog.InfoContext(ctx, "updated oauth account tokens",
			"user_id", userRecord.ID,
			"provider", req.ProviderID,
			"account_id", accountRecord.ID,
		)
	}

	// Sync user profile data from OAuth provider (if not a new user)
	if !isNewUser {
		syncReq := &SyncProviderDataRequest{
			UserID:     userRecord.ID,
			ProviderID: req.ProviderID,
			OAuthUser:  req.OAuthUser,
			UpdateUser: true,
		}

		_, err = s.SyncProviderData(ctx, syncReq)
		if err != nil {
			// Log the error but don't fail the signin
			slog.WarnContext(ctx, "failed to sync provider data",
				"user_id", userRecord.ID,
				"provider", req.ProviderID,
				"error", err,
			)
		}

		// Reload user after sync
		userRecord, err = s.userRepo.FindByID(userRecord.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to reload user after sync: %w", err)
		}
	}

	// Create a new session
	sessionToken, err := crypto.GenerateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    userRecord.ID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = s.sessionRepo.Create(sess)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &OAuthSignInResponse{
		User:      userRecord,
		Session:   sess,
		Account:   accountRecord,
		IsNewUser: isNewUser,
	}, nil
}

// createUserFromOAuth creates a new user from OAuth profile data
func (s *Service) createUserFromOAuth(ctx context.Context, oauthUser *account.OAuthUser) (*user.User, error) {
	newUser := &user.User{
		ID:            uuid.New().String(),
		Email:         oauthUser.Email,
		Name:          oauthUser.Name,
		EmailVerified: true, // OAuth providers verify emails
		Image:         oauthUser.Picture,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err := s.userRepo.Create(newUser)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return newUser, nil
}

// linkOAuthAccountInternal links an OAuth account to a user (internal helper)
func (s *Service) linkOAuthAccountInternal(ctx context.Context, userID string, providerID account.ProviderType, oauthUser *account.OAuthUser, tokens *account.OAuthTokens) (*account.Account, error) {
	newAccount := &account.Account{
		ID:                    uuid.New().String(),
		UserID:                userID,
		ProviderID:            providerID,
		AccountID:             oauthUser.ID,
		AccessToken:           &tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		IDToken:               tokens.IDToken,
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
		Scope:                 &tokens.Scope,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	err := s.accountRepo.Create(newAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	return newAccount, nil
}
