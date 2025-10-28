package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// SendEmailVerificationRequest contains the request data for sending an email verification
type SendEmailVerificationRequest struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callback_url,omitempty"`
}

// SendEmailVerificationResponse contains the response data for sending email verification
type SendEmailVerificationResponse struct {
	Status bool `json:"status"`
}

// SendEmailVerification is the use case for sending an email verification
func (s *Service) SendEmailVerification(ctx context.Context, req *SendEmailVerificationRequest) (*SendEmailVerificationResponse, error) {
	if !s.config.EmailVerification.Enabled {
		return nil, fmt.Errorf("send email verification feature is disabled")
	}

	if req == nil {
		return nil, fmt.Errorf("send email verification request cannot be nil")
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
	verification := &verification.Verification{
		Identifier: req.Email,
		Token:      verificationToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour), // 7 days
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.verificationRepo.Create(verification); err != nil {
		return nil, fmt.Errorf("failed to create email verification token: %w", err)
	}

	// Send verification email if configured
	if s.config.EmailVerification != nil && s.config.EmailVerification.SendVerificationEmail != nil {
		// Find user by email
		user, err := s.userRepo.FindByEmail(req.Email)
		if err == nil && user != nil {
			go s.sendVerificationEmailForRequestAsync(ctx, user, verificationToken, req.CallbackURL)
		}
	}

	return &SendEmailVerificationResponse{
		Status: true,
	}, nil
}

// sendVerificationEmailForRequestAsync sends a verification email asynchronously for manual verification requests
func (s *Service) sendVerificationEmailForRequestAsync(ctx context.Context, user *user.User, verificationToken string, callbackURL string) {
	// Build verification URL
	baseURL := s.config.BaseURL
	basePath := s.config.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	callbackURLValue := ""
	if callbackURL != "" {
		callbackURLValue = "&callbackURL=" + url.QueryEscape(callbackURL)
	}
	verifyURL := baseURL + basePath + "/verify-email?token=" + url.QueryEscape(verificationToken) + callbackURLValue

	// Send email
	if err := s.config.EmailVerification.SendVerificationEmail(ctx, user, verifyURL, verificationToken); err != nil {
		slog.ErrorContext(ctx, "failed to send verification email", "user_id", user.ID, "email", user.Email, "error", err)
		return
	}

	slog.InfoContext(ctx, "verification email sent", "user_id", user.ID, "email", user.Email)
}
