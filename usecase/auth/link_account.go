package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/google/uuid"
)

// LinkOAuthAccountRequest represents a request to link an OAuth account to a user
type LinkOAuthAccountRequest struct {
	UserID       string
	ProviderID   account.ProviderType
	AccountID    string
	AccessToken  string
	RefreshToken *string
	IDToken      *string
	Scope        *string
}

// UnlinkOAuthAccountRequest represents a request to unlink an OAuth account from a user
type UnlinkOAuthAccountRequest struct {
	UserID     string
	ProviderID account.ProviderType
}

// LinkOAuthAccountResponse represents the response from linking an OAuth account
type LinkOAuthAccountResponse struct {
	Account *account.Account `json:"account"`
}

// UnlinkOAuthAccountResponse represents the response from unlinking an OAuth account
type UnlinkOAuthAccountResponse struct {
	Success bool `json:"success"`
}

// LinkOAuthAccount links an OAuth account to a user
func (s *Service) LinkOAuthAccount(ctx context.Context, req *LinkOAuthAccountRequest) (*LinkOAuthAccountResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.UserID == "" {
		return nil, fmt.Errorf("user_id cannot be empty")
	}

	if req.ProviderID == "" {
		return nil, fmt.Errorf("provider_id cannot be empty")
	}

	if req.AccountID == "" {
		return nil, fmt.Errorf("account_id cannot be empty")
	}

	if req.AccessToken == "" {
		return nil, fmt.Errorf("access_token cannot be empty")
	}

	// Check if user exists
	user, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if account with this provider already exists for this user
	existingAccount, err := s.accountRepo.FindByUserIDAndProvider(req.UserID, req.ProviderID)
	if err == nil && existingAccount != nil {
		// Account already linked
		return nil, fmt.Errorf("account with provider %s is already linked to this user", req.ProviderID)
	}

	// Create new account
	newAccount := &account.Account{
		ID:           uuid.New().String(),
		UserID:       req.UserID,
		ProviderID:   req.ProviderID,
		AccountID:    req.AccountID,
		AccessToken:  &req.AccessToken,
		RefreshToken: req.RefreshToken,
		IDToken:      req.IDToken,
		Scope:        req.Scope,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err = s.accountRepo.Create(newAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	return &LinkOAuthAccountResponse{
		Account: newAccount,
	}, nil
}

// UnlinkOAuthAccount unlinks an OAuth account from a user
func (s *Service) UnlinkOAuthAccount(ctx context.Context, req *UnlinkOAuthAccountRequest) (*UnlinkOAuthAccountResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.UserID == "" {
		return nil, fmt.Errorf("user_id cannot be empty")
	}

	if req.ProviderID == "" {
		return nil, fmt.Errorf("provider_id cannot be empty")
	}

	// Check if account exists
	account, err := s.accountRepo.FindByUserIDAndProvider(req.UserID, req.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}

	if account == nil {
		return nil, fmt.Errorf("account not found")
	}

	// Delete the account
	err = s.accountRepo.Delete(account.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete account: %w", err)
	}

	return &UnlinkOAuthAccountResponse{
		Success: true,
	}, nil
}

// GetLinkedAccounts returns all OAuth accounts linked to a user
func (s *Service) GetLinkedAccounts(ctx context.Context, userID string) ([]*account.Account, error) {
	if userID == "" {
		return nil, fmt.Errorf("user_id cannot be empty")
	}

	// Check if user exists
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get all accounts for the user
	accounts, err := s.accountRepo.FindByUserID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts: %w", err)
	}

	if accounts == nil {
		accounts = make([]*account.Account, 0)
	}

	return accounts, nil
}

// HasLinkedAccount checks if a user has an account linked with a specific provider
func (s *Service) HasLinkedAccount(ctx context.Context, userID string, providerID account.ProviderType) (bool, error) {
	if userID == "" {
		return false, fmt.Errorf("user_id cannot be empty")
	}

	if providerID == "" {
		return false, fmt.Errorf("provider_id cannot be empty")
	}

	// Check if account exists
	return s.accountRepo.ExistsByUserIDAndProvider(userID, providerID)
}

// UpdateLinkedAccountTokens updates the tokens for a linked OAuth account
func (s *Service) UpdateLinkedAccountTokens(ctx context.Context, userID string, providerID account.ProviderType, accessToken string, refreshToken *string, expiresAt *time.Time) error {
	if userID == "" {
		return fmt.Errorf("user_id cannot be empty")
	}

	if providerID == "" {
		return fmt.Errorf("provider_id cannot be empty")
	}

	if accessToken == "" {
		return fmt.Errorf("access_token cannot be empty")
	}

	// Get the existing account
	acc, err := s.accountRepo.FindByUserIDAndProvider(userID, providerID)
	if err != nil {
		return fmt.Errorf("account not found: %w", err)
	}

	if acc == nil {
		return fmt.Errorf("account not found")
	}

	// Update tokens
	acc.AccessToken = &accessToken
	if refreshToken != nil {
		acc.RefreshToken = refreshToken
	}
	if expiresAt != nil {
		acc.AccessTokenExpiresAt = expiresAt
	}
	acc.UpdatedAt = time.Now()

	err = s.accountRepo.Update(acc)
	if err != nil {
		return fmt.Errorf("failed to update account: %w", err)
	}

	return nil
}
