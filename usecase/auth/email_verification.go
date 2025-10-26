package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// RequestEmailVerificationRequest contains the request data for requesting email verification
type RequestEmailVerificationRequest struct {
	Email string `json:"email"`
}

// RequestEmailVerificationResponse contains the response data for requesting email verification
type RequestEmailVerificationResponse struct {
	Verification *verification.Verification `json:"verification"`
}

// RequestEmailVerification is the use case for requesting email verification
func (s *Service) RequestEmailVerification(ctx context.Context, req *RequestEmailVerificationRequest) (*RequestEmailVerificationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request email verification request cannot be nil")
	}

	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}

	// Generate verification token
	verificationToken, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Create verification record
	v := &verification.Verification{
		ID:         uuid.New().String(),
		Identifier: req.Email,
		Token:      verificationToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour), // 7 days
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.verificationRepo.Create(v); err != nil {
		return nil, fmt.Errorf("failed to create email verification token: %w", err)
	}

	// Send verification email if configured
	if s.config.EmailVerification != nil && s.config.EmailVerification.SendVerificationEmail != nil {
		// Find user by email
		user, err := s.userRepo.FindByEmail(req.Email)
		if err == nil && user != nil {
			go s.sendVerificationEmailForRequestAsync(ctx, user, verificationToken)
		}
	}

	return &RequestEmailVerificationResponse{
		Verification: v,
	}, nil
}

// sendVerificationEmailForRequestAsync sends a verification email asynchronously for manual verification requests
func (s *Service) sendVerificationEmailForRequestAsync(ctx context.Context, u *user.User, verificationToken string) {
	// Build verification URL
	baseURL := s.config.BaseURL
	basePath := s.config.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	verifyURL := baseURL + basePath + "/verify-email?token=" + url.QueryEscape(verificationToken)

	// Send email
	if err := s.config.EmailVerification.SendVerificationEmail(ctx, u, verifyURL, verificationToken); err != nil {
		slog.ErrorContext(ctx, "failed to send verification email", "user_id", u.ID, "email", u.Email, "error", err)
		return
	}

	slog.InfoContext(ctx, "verification email sent", "user_id", u.ID, "email", u.Email)
}

// VerifyEmailRequest contains the request data for verifying an email
type VerifyEmailRequest struct {
	VerificationToken string `json:"verification_token"`
}

// VerifyEmailResponse contains the response data for verifying an email
type VerifyEmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// VerifyEmail is the use case for verifying a user's email address
func (s *Service) VerifyEmail(req *VerifyEmailRequest) (*VerifyEmailResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("verify email request cannot be nil")
	}

	if req.VerificationToken == "" {
		return nil, fmt.Errorf("verification token is required")
	}

	// Find verification token
	v, err := s.verificationRepo.FindByToken(req.VerificationToken)
	if err != nil {
		return nil, fmt.Errorf("failed to find verification token: %w", err)
	}

	if v == nil || v.Type != verification.TypeEmailVerification {
		return nil, fmt.Errorf("invalid verification token")
	}

	// Check if token has expired
	if v.IsExpired() {
		return nil, fmt.Errorf("verification token has expired")
	}

	// Find user by email
	userFound, err := s.userRepo.FindByEmail(v.Identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if userFound == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Mark email as verified
	userFound.EmailVerified = true
	userFound.UpdatedAt = time.Now()

	if err := s.userRepo.Update(userFound); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Delete verification token
	_ = s.verificationRepo.Delete(v.ID)

	return &VerifyEmailResponse{
		Success: true,
		Message: "Email verified.",
	}, nil
}
