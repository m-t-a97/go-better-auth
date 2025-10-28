package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
)

// VerifyEmailRequest contains the request data for verifying an email (unified endpoint)
type VerifyEmailRequest struct {
	VerificationToken string `json:"token" validate:"required"`
}

// VerifyEmailResponse contains the response data for verifying an email
type VerifyEmailResponse struct {
	Status bool `json:"status"`
}

// VerifyEmail is the unified use case for handling all verification types
// It uses the strategy pattern to route to the appropriate handler based on verification type
func (s *Service) VerifyEmail(ctx context.Context, req *VerifyEmailRequest) (*VerifyEmailResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("verify email request cannot be nil")
	}

	if req.VerificationToken == "" {
		return nil, fmt.Errorf("verification token is required")
	}

	// Find verification token
	verif, err := s.verificationRepo.FindByToken(req.VerificationToken)
	if err != nil {
		return nil, fmt.Errorf("failed to find verification token: %w", err)
	}

	if verif == nil {
		return nil, fmt.Errorf("invalid verification token")
	}

	// Check if token has expired
	if verif.IsExpired() {
		return nil, fmt.Errorf("verification token has expired")
	}

	// Route to appropriate handler based on verification type
	switch verif.Type {
	case verification.TypeEmailVerification:
		if err := s.handleEmailVerification(verif); err != nil {
			return nil, err
		}
	case verification.TypeEmailChange:
		if err := s.handleEmailChange(verif); err != nil {
			return nil, err
		}
	case verification.TypePasswordReset:
		if err := s.handlePasswordReset(verif); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown verification type: %s", verif.Type)
	}

	return &VerifyEmailResponse{
		Status: true,
	}, nil
}

// handleEmailVerification handles email verification type
func (s *Service) handleEmailVerification(verif *verification.Verification) error {
	// Find user by email (identifier in this case)
	userFound, err := s.userRepo.FindByEmail(verif.Identifier)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if userFound == nil {
		return fmt.Errorf("user not found")
	}

	// Mark email as verified
	userFound.EmailVerified = true
	userFound.UpdatedAt = time.Now()

	if err := s.userRepo.Update(userFound); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Delete verification token
	_ = s.verificationRepo.Delete(verif.ID)

	return nil
}

// handleEmailChange handles email change type
func (s *Service) handleEmailChange(verif *verification.Verification) error {
	// The verif.Identifier contains the new email address
	newEmail := verif.Identifier

	// Check if new email is still available (safety check)
	emailExists, err := s.userRepo.ExistsByEmail(newEmail)
	if err != nil {
		return fmt.Errorf("failed to check email existence: %w", err)
	}

	if emailExists {
		return fmt.Errorf("email is already in use")
	}

	// Validate email format
	if err := user.ValidateEmail(newEmail); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	// Find user by user ID stored in verification record
	userToUpdate, err := s.userRepo.FindByID(verif.UserID)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if userToUpdate == nil {
		return fmt.Errorf("user not found")
	}

	// Update user's email
	userToUpdate.Email = newEmail
	userToUpdate.UpdatedAt = time.Now()

	if err := s.userRepo.Update(userToUpdate); err != nil {
		return fmt.Errorf("failed to update user email: %w", err)
	}

	// Delete verification token
	_ = s.verificationRepo.Delete(verif.ID)

	return nil
}

// handlePasswordReset handles password reset type
func (s *Service) handlePasswordReset(verif *verification.Verification) error {
	// Find user by email (identifier in this case)
	userFound, err := s.userRepo.FindByEmail(verif.Identifier)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if userFound == nil {
		return fmt.Errorf("user not found")
	}

	// Delete verification token
	_ = s.verificationRepo.Delete(verif.ID)

	return nil
}
