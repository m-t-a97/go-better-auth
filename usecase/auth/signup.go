package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/user"
)

// SignUpRequest contains the request data for sign up
type SignUpRequest struct {
	Email    string
	Password string
	Name     string
}

// SignUpResponse contains the response data for sign up
type SignUpResponse struct {
	User *user.User
}

// SignUp is the use case for user sign up with email and password
func (s *Service) SignUp(req *SignUpRequest) (*SignUpResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("sign up request cannot be nil")
	}

	// Validate request
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Check if user already exists
	exists, err := s.userRepo.ExistsByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check if user exists: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("user with this email already exists")
	}

	// Hash password
	hashedPassword, err := s.passwordHasher.Hash(strings.TrimSpace(req.Password))
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	u := &user.User{
		ID:            uuid.New().String(),
		Email:         strings.TrimSpace(req.Email),
		Name:          strings.TrimSpace(req.Name),
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Create account for email/password
	acc := &account.Account{
		ID:         uuid.New().String(),
		UserID:     u.ID,
		ProviderID: account.ProviderCredential,
		Password:   &hashedPassword,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save user and account
	if err := s.userRepo.Create(u); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if err := s.accountRepo.Create(acc); err != nil {
		// Cleanup on failure
		_ = s.userRepo.Delete(u.ID)
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	return &SignUpResponse{User: u}, nil
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
