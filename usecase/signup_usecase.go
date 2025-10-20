package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain"
)

// signUpUseCase handles user registration business logic
type signUpUseCase struct {
	userRepo         UserRepository
	accountRepo      AccountRepository
	verificationRepo VerificationRepository
	passwordHasher   PasswordHasher
	emailSender      EmailSender
	sessionRepo      SessionRepository
	config           *domain.AuthConfig
}

// NewSignUpUseCase creates a new sign up use case
func NewSignUpUseCase(
	userRepo UserRepository,
	accountRepo AccountRepository,
	verificationRepo VerificationRepository,
	passwordHasher PasswordHasher,
	emailSender EmailSender,
	sessionRepo SessionRepository,
	config *domain.AuthConfig,
) SignUpUseCase {
	return &signUpUseCase{
		userRepo:         userRepo,
		accountRepo:      accountRepo,
		verificationRepo: verificationRepo,
		passwordHasher:   passwordHasher,
		emailSender:      emailSender,
		sessionRepo:      sessionRepo,
		config:           config,
	}
}

// SignUpEmail registers a new user with email and password
func (uc *signUpUseCase) SignUpEmail(ctx context.Context, input *domain.SignUpEmailInput) (*domain.SignUpEmailOutput, error) {
	// Validate password policy
	if err := ValidatePassword(input.Password); err != nil {
		return nil, err
	}

	// Check if user already exists
	existingUser, err := uc.userRepo.FindByEmail(ctx, input.Email)
	if err == nil && existingUser != nil {
		return nil, domain.ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := uc.passwordHasher.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &domain.User{
		ID:            uuid.New().String(),
		Email:         input.Email,
		Name:          input.Name,
		Image:         input.Image,
		EmailVerified: !uc.config.RequireEmailVerification,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Create account with hashed password
	account := &domain.Account{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		AccountID:  user.Email,
		ProviderId: "credential",
		Password:   &hashedPassword,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := uc.accountRepo.Create(ctx, account); err != nil {
		return nil, err
	}

	// Send verification email if required
	if uc.config.RequireEmailVerification && uc.emailSender != nil {
		token := GenerateToken()
		verification := &domain.Verification{
			ID:         uuid.New().String(),
			Identifier: user.Email,
			Value:      token,
			ExpiresAt:  time.Now().Add(uc.config.VerificationTokenExpiry),
			CreatedAt:  time.Now(),
		}

		if err := uc.verificationRepo.Create(ctx, verification); err != nil {
			return nil, err
		}

		url := uc.config.BaseURL + "/auth/verify-email?token=" + token
		if err := uc.emailSender.SendVerificationEmail(ctx, user.Email, token, url); err != nil {
			// Log error but don't fail signup
		}
	}

	var session *domain.Session
	// Auto sign in if enabled and email verification not required or not enabled
	if uc.config.AutoSignIn && (!uc.config.RequireEmailVerification || user.EmailVerified) {
		session, err = uc.createSession(ctx, user.ID, nil, nil)
		if err != nil {
			return nil, err
		}
	}

	return &domain.SignUpEmailOutput{
		User:    user,
		Session: session,
	}, nil
}

// createSession is a helper to create a session
func (uc *signUpUseCase) createSession(ctx context.Context, userID string, ipAddress, userAgent *string) (*domain.Session, error) {
	session := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     GenerateToken(),
		ExpiresAt: time.Now().Add(uc.config.SessionExpiresIn),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := uc.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}
