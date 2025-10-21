package auth

import (
	"fmt"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// RequestChangeEmailRequest contains the request data for requesting an email change
type RequestChangeEmailRequest struct {
	UserID   string
	NewEmail string
}

// RequestChangeEmailResponse contains the response data for requesting an email change
type RequestChangeEmailResponse struct {
	Verification *verification.Verification
}

// RequestChangeEmail is the use case for requesting an email change
// It generates a verification token that must be confirmed before the email is changed
func (s *Service) RequestChangeEmail(req *RequestChangeEmailRequest) (*RequestChangeEmailResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request change email request cannot be nil")
	}

	if req.UserID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	if req.NewEmail == "" {
		return nil, fmt.Errorf("new email is required")
	}

	// Validate email format
	if err := user.ValidateEmail(req.NewEmail); err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	// Check if user exists
	existingUser, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if existingUser == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if new email is the same as current email
	if existingUser.Email == req.NewEmail {
		return nil, fmt.Errorf("new email is the same as current email")
	}

	// Check if new email is already in use by another user
	emailExists, err := s.userRepo.ExistsByEmail(req.NewEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}

	if emailExists {
		return nil, fmt.Errorf("email is already in use")
	}

	// Generate verification token
	verificationToken, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Create verification record
	// Store the new email as the identifier
	v := &verification.Verification{
		Identifier: req.NewEmail,
		Token:      verificationToken,
		Type:       verification.TypeEmailChange,
		ExpiresAt:  time.Now().Add(24 * time.Hour), // 1 day
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.verificationRepo.Create(v); err != nil {
		return nil, fmt.Errorf("failed to create email change verification token: %w", err)
	}

	return &RequestChangeEmailResponse{
		Verification: v,
	}, nil
}

// ConfirmChangeEmailRequest contains the request data for confirming an email change
type ConfirmChangeEmailRequest struct {
	UserID            string
	VerificationToken string
}

// ConfirmChangeEmailResponse contains the response data for confirming an email change
type ConfirmChangeEmailResponse struct {
	User *user.User
}

// ConfirmChangeEmail is the use case for confirming an email change
// It verifies the token and updates the user's email address
func (s *Service) ConfirmChangeEmail(req *ConfirmChangeEmailRequest) (*ConfirmChangeEmailResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("confirm change email request cannot be nil")
	}

	if req.UserID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	if req.VerificationToken == "" {
		return nil, fmt.Errorf("verification token is required")
	}

	// Find verification token
	v, err := s.verificationRepo.FindByToken(req.VerificationToken)
	if err != nil {
		return nil, fmt.Errorf("failed to find verification token: %w", err)
	}

	if v == nil || v.Type != verification.TypeEmailChange {
		return nil, fmt.Errorf("invalid verification token")
	}

	// Check if token has expired
	if v.IsExpired() {
		return nil, fmt.Errorf("verification token has expired")
	}

	// Find user by ID
	u, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if new email is still available (safety check)
	emailExists, err := s.userRepo.ExistsByEmail(v.Identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}

	if emailExists && v.Identifier != u.Email {
		return nil, fmt.Errorf("email is already in use")
	}

	// Update user's email
	u.Email = v.Identifier
	u.UpdatedAt = time.Now()

	if err := s.userRepo.Update(u); err != nil {
		return nil, fmt.Errorf("failed to update user email: %w", err)
	}

	// Delete verification token
	_ = s.verificationRepo.Delete(v.ID)

	return &ConfirmChangeEmailResponse{
		User: u,
	}, nil
}
