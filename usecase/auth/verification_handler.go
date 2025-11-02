package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
)

// VerifyEmailRequest contains the request data for verifying an email (unified endpoint)
type VerifyEmailRequest struct {
	VerificationToken string `json:"token" validate:"required"`
}

// VerifyEmailResponse contains the response data for verifying an email
type VerifyEmailResponse struct {
	Status bool                          `json:"status"`
	Type   verification.VerificationType `json:"type"`
	Token  string                        `json:"token,omitempty"`
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

	// Find verification token by matching the plain token against hashed tokens
	verificationRecord, err := s.verificationRepo.FindByHashedToken(req.VerificationToken)
	if err != nil {
		return nil, fmt.Errorf("failed to find verification token: %w", err)
	}

	if verificationRecord == nil {
		return nil, fmt.Errorf("invalid verification token")
	}

	if verificationRecord.IsExpired() {
		return nil, fmt.Errorf("verification token has expired")
	}

	var token string

	// Route to appropriate handler based on verification type
	switch verificationRecord.Type {
	case verification.TypeEmailVerification:
		if err := s.handleEmailVerification(verificationRecord); err != nil {
			return nil, err
		}
	case verification.TypeEmailChange:
		if err := s.handleEmailChange(verificationRecord); err != nil {
			return nil, err
		}
	case verification.TypePasswordReset:
		if err := s.handlePasswordReset(verificationRecord); err != nil {
			return nil, err
		}
		token = verificationRecord.Token
	default:
		return nil, fmt.Errorf("unknown verification type: %s", verificationRecord.Type)
	}

	return &VerifyEmailResponse{
		Status: true,
		Type:   verificationRecord.Type,
		Token:  token,
	}, nil
}

// handleEmailVerification handles email verification type
func (s *Service) handleEmailVerification(verif *verification.Verification) error {
	userFound, err := s.userRepo.FindByEmail(verif.Identifier)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if userFound == nil {
		return fmt.Errorf("user not found")
	}

	userFound.EmailVerified = true
	userFound.UpdatedAt = time.Now()

	if err := s.userRepo.Update(userFound); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	_ = s.verificationRepo.Delete(verif.ID)

	return nil
}

func (s *Service) handleEmailChange(verif *verification.Verification) error {
	newEmail := verif.Identifier

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

	userToUpdate, err := s.userRepo.FindByID(verif.UserID)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if userToUpdate == nil {
		return fmt.Errorf("user not found")
	}

	userToUpdate.Email = newEmail
	userToUpdate.UpdatedAt = time.Now()

	if err := s.userRepo.Update(userToUpdate); err != nil {
		return fmt.Errorf("failed to update user email: %w", err)
	}

	_ = s.verificationRepo.Delete(verif.ID)

	return nil
}

// handlePasswordReset handles password reset type
func (s *Service) handlePasswordReset(verif *verification.Verification) error {
	userFound, err := s.userRepo.FindByEmail(verif.Identifier)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if userFound == nil {
		return fmt.Errorf("user not found")
	}

	return nil
}
