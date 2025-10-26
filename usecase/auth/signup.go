package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// SignUpRequest contains the request data for sign up
type SignUpRequest struct {
	Email    string
	Password string
	Name     string
}

// SignUpResponse contains the response data for sign up
type SignUpResponse struct {
	Session *session.Session
	User    *user.User
}

// SignUp is the use case for user sign up with email and password
func (s *Service) SignUp(ctx context.Context, req *SignUpRequest) (*SignUpResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("sign up request cannot be nil")
	}

	// Check if email/password auth is disabled
	if s.config.EmailAndPassword != nil && s.config.EmailAndPassword.DisableSignUp {
		return nil, fmt.Errorf("email/password is disabled")
	}

	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	exists, err := s.userRepo.ExistsByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check if user exists: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("user with this email already exists")
	}

	hashedPassword, err := s.passwordHasher.Hash(strings.TrimSpace(req.Password))
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	userToCreate := &user.User{
		ID:    uuid.New().String(),
		Email: strings.TrimSpace(req.Email),
		Name:  strings.TrimSpace(req.Name),
		// If email verification is not enabled, mark as verified automatically
		EmailVerified: s.config.EmailVerification == nil,
		Image:         nil,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	accountToCreate := &account.Account{
		ID:         uuid.New().String(),
		UserID:     userToCreate.ID,
		ProviderID: account.ProviderCredential,
		AccountID:  userToCreate.ID,
		Password:   &hashedPassword,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save user and account
	if err := s.userRepo.Create(userToCreate); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if err := s.accountRepo.Create(accountToCreate); err != nil {
		// Cleanup on failure
		_ = s.userRepo.Delete(userToCreate.ID)
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	// Generate session token
	sessionToken, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create session
	sessionCreated := &session.Session{
		ID:        uuid.New().String(),
		UserID:    userToCreate.ID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 day session
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save session
	if err := s.sessionRepo.Create(sessionCreated); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Send verification email if configured
	if s.config.EmailVerification != nil && s.config.EmailVerification.SendOnSignUp && s.config.EmailVerification.SendVerificationEmail != nil {
		go s.sendVerificationEmail(ctx, userToCreate)
	}

	return &SignUpResponse{Session: sessionCreated, User: userToCreate}, nil
}

func (s *Service) sendVerificationEmail(ctx context.Context, user *user.User) {
	// Generate verification token
	verificationToken, err := crypto.GenerateToken(32)
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate verification token", "user_id", user.ID, "error", err)
		return
	}

	// Create verification record
	newVerification := &verification.Verification{
		ID:         uuid.New().String(),
		Identifier: user.Email,
		Token:      verificationToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(s.config.EmailVerification.ExpiresIn),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.verificationRepo.Create(newVerification); err != nil {
		slog.ErrorContext(ctx, "failed to create email verification token", "user_id", user.ID, "error", err)
		return
	}

	// Build verification URL
	baseURL := s.config.BaseURL
	basePath := s.config.BasePath
	if basePath == "" {
		basePath = "/auth"
	}
	verifyURL := baseURL + basePath + "/verify-email?token=" + url.QueryEscape(verificationToken)

	// Send email
	if err := s.config.EmailVerification.SendVerificationEmail(ctx, user, verifyURL, verificationToken); err != nil {
		slog.ErrorContext(ctx, "failed to send verification email", "user_id", user.ID, "email", user.Email, "error", err)
		return
	}

	slog.InfoContext(ctx, "verification email sent", "user_id", user.ID, "email", user.Email)
}

// Validate validates the sign up request
func (req *SignUpRequest) Validate() error {
	if strings.TrimSpace(req.Email) == "" {
		return fmt.Errorf("email is required")
	}

	if strings.TrimSpace(req.Password) == "" {
		return fmt.Errorf("password is required")
	}

	if len(strings.TrimSpace(req.Password)) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("name is required")
	}

	return nil
}
