package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// SignInRequest contains the request data for sign in
type SignInRequest struct {
	Email       string
	Password    string
	CallbackURL string
	IPAddress   string
	UserAgent   string
}

// SignInResponse contains the response data for sign in
type SignInResponse struct {
	Session *session.Session
	User    *user.User
}

// SignIn is the use case for user sign in with email and password
func (s *Service) SignIn(ctx context.Context, req *SignInRequest) (*SignInResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("sign in request cannot be nil")
	}

	// Validate request
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Check brute force protection
	if s.bruteForceService != nil {
		if err := s.bruteForceService.CheckLoginAttempt(req.Email, req.IPAddress); err != nil {
			return nil, fmt.Errorf("account is temporarily locked")
		}
	}

	// Find user by email
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		// Record failed attempt on brute force
		if s.bruteForceService != nil {
			_ = s.bruteForceService.RecordFailedAttempt(req.Email, req.IPAddress)
		}
		return nil, fmt.Errorf("invalid email or password")
	}

	// Find account for this user (credential provider)
	acc, err := s.accountRepo.FindByUserIDAndProvider(user.ID, "credential")
	if err != nil {
		// Record failed attempt on brute force
		if s.bruteForceService != nil {
			_ = s.bruteForceService.RecordFailedAttempt(req.Email, req.IPAddress)
		}
		return nil, fmt.Errorf("invalid email or password")
	}

	// Verify password
	if acc.Password == nil || *acc.Password == "" {
		// Record failed attempt on brute force
		if s.bruteForceService != nil {
			_ = s.bruteForceService.RecordFailedAttempt(req.Email, req.IPAddress)
		}
		return nil, fmt.Errorf("invalid email or password")
	}

	ok, err := s.passwordHasher.Verify(req.Password, *acc.Password)
	if err != nil || !ok {
		// Record failed attempt on brute force
		if s.bruteForceService != nil {
			_ = s.bruteForceService.RecordFailedAttempt(req.Email, req.IPAddress)
		}
		return nil, fmt.Errorf("invalid email or password")
	}

	// Clear attempts on successful login
	if s.bruteForceService != nil {
		_ = s.bruteForceService.ClearAttempts(req.Email)
	}

	// Generate session token
	sessionToken, err := crypto.GenerateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create session with pointers for optional fields
	ipAddr := req.IPAddress
	userAgent := req.UserAgent
	sessionCreated := &session.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     sessionToken,
		IPAddress: &ipAddr,
		UserAgent: &userAgent,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 day session
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save session
	if err := s.sessionRepo.Create(sessionCreated); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Send verification email if configured and email not verified
	if s.config.EmailVerification != nil && s.config.EmailVerification.SendOnSignIn && !user.EmailVerified && s.config.EmailVerification.SendVerificationEmail != nil {
		// Generate verification token
		verificationToken, err := crypto.GenerateVerificationToken()
		if err == nil {
			// Hash the token for secure storage
			hashedToken := crypto.HashVerificationToken(verificationToken)

			// Create verification record with hashed token
			verificationCreated := &verification.Verification{
				Identifier: user.Email,
				Token:      hashedToken,
				Type:       verification.TypeEmailVerification,
				ExpiresAt:  time.Now().Add(s.config.EmailVerification.ExpiresIn),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}

			if err := s.verificationRepo.Create(verificationCreated); err == nil {
				// Build verification URL using the plain token
				baseURL := s.config.BaseURL
				basePath := s.config.BasePath
				if basePath == "" {
					basePath = "/api/auth"
				}

				callbackURLValue := ""
				if req.CallbackURL != "" {
					callbackURLValue = "&callbackURL=" + url.QueryEscape(req.CallbackURL)
				}
				verifyURL := baseURL + basePath + "/verify-email?token=" + url.QueryEscape(verificationToken) + callbackURLValue

				// Send email asynchronously with plain token
				go func() {
					if err := s.config.EmailVerification.SendVerificationEmail(ctx, user, verifyURL, verificationToken); err != nil {
						slog.ErrorContext(ctx, "failed to send verification email on sign in", "user_id", user.ID, "email", user.Email, "error", err)
						return
					}
					slog.InfoContext(ctx, "verification email sent on sign in", "user_id", user.ID, "email", user.Email)
				}()
			}
		}
	}

	return &SignInResponse{Session: sessionCreated, User: user}, nil
}

// Validate validates the sign in request
func (req *SignInRequest) Validate() error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}

	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	return nil
}
