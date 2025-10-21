package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// RequestPasswordResetRequest contains the request data for requesting a password reset
type RequestPasswordResetRequest struct {
	Email string
}

// RequestPasswordResetResponse contains the response data for requesting a password reset
type RequestPasswordResetResponse struct {
	Verification *verification.Verification
}

// RequestPasswordReset is the use case for requesting a password reset
func (s *Service) RequestPasswordReset(req *RequestPasswordResetRequest) (*RequestPasswordResetResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request password reset request cannot be nil")
	}

	if strings.TrimSpace(req.Email) == "" {
		return nil, fmt.Errorf("email is required")
	}

	// Find user by email
	u, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate reset token
	resetToken, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Create verification record
	v := &verification.Verification{
		Identifier: u.Email,
		Token:      resetToken,
		Type:       verification.TypePasswordReset,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.verificationRepo.Create(v); err != nil {
		return nil, fmt.Errorf("failed to create password reset token: %w", err)
	}

	return &RequestPasswordResetResponse{
		Verification: v,
	}, nil
}

// ResetPasswordRequest contains the request data for resetting a password
type ResetPasswordRequest struct {
	ResetToken  string
	NewPassword string
}

// ResetPasswordResponse contains the response data for resetting a password
type ResetPasswordResponse struct {
	Success bool
}

// ResetPassword is the use case for resetting a user's password
func (s *Service) ResetPassword(req *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("reset password request cannot be nil")
	}

	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Find verification token
	v, err := s.verificationRepo.FindByToken(req.ResetToken)
	if err != nil {
		return nil, fmt.Errorf("failed to find reset token: %w", err)
	}

	if v == nil || v.Type != verification.TypePasswordReset {
		return nil, fmt.Errorf("invalid reset token")
	}

	// Check if token has expired
	if v.IsExpired() {
		return nil, fmt.Errorf("reset token has expired")
	}

	// Find user by email
	u, err := s.userRepo.FindByEmail(v.Identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Find user's account
	acc, err := s.accountRepo.FindByUserIDAndProvider(u.ID, account.ProviderCredential)
	if err != nil {
		return nil, fmt.Errorf("failed to find account: %w", err)
	}

	if acc == nil {
		return nil, fmt.Errorf("account not found")
	}

	// Hash new password
	hashedPassword, err := s.passwordHasher.Hash(strings.TrimSpace(req.NewPassword))
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update account password
	acc.Password = &hashedPassword
	acc.UpdatedAt = time.Now()

	if err := s.accountRepo.Update(acc); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Delete verification token
	_ = s.verificationRepo.Delete(v.ID)

	return &ResetPasswordResponse{
		Success: true,
	}, nil
}

// Validate validates the reset password request
func (req *ResetPasswordRequest) Validate() error {
	if req.ResetToken == "" {
		return fmt.Errorf("reset token is required")
	}

	if strings.TrimSpace(req.NewPassword) == "" {
		return fmt.Errorf("new password is required")
	}

	if len(strings.TrimSpace(req.NewPassword)) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	return nil
}
