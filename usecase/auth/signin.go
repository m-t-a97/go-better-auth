package auth

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/internal/crypto"
)

// SignInRequest contains the request data for sign in
type SignInRequest struct {
	Email     string
	Password  string
	IPAddress string
	UserAgent string
}

// SignInResponse contains the response data for sign in
type SignInResponse struct {
	Session *session.Session
}

// SignIn is the use case for user sign in with email and password
func (s *Service) SignIn(req *SignInRequest) (*SignInResponse, error) {
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
	u, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		// Record failed attempt on brute force
		if s.bruteForceService != nil {
			_ = s.bruteForceService.RecordFailedAttempt(req.Email, req.IPAddress)
		}
		return nil, fmt.Errorf("invalid email or password")
	}

	// Find account for this user (credential provider)
	acc, err := s.accountRepo.FindByUserIDAndProvider(u.ID, "credential")
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
	sessionToken, err := crypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create session with pointers for optional fields
	ipAddr := req.IPAddress
	userAgent := req.UserAgent
	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    u.ID,
		Token:     sessionToken,
		IPAddress: &ipAddr,
		UserAgent: &userAgent,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save session
	if err := s.sessionRepo.Create(sess); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &SignInResponse{Session: sess}, nil
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
