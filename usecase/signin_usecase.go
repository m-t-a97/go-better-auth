package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain"
)

// signInUseCase handles user authentication business logic
type signInUseCase struct {
	userRepo         UserRepository
	accountRepo      AccountRepository
	sessionRepo      SessionRepository
	verificationRepo VerificationRepository
	passwordHasher   PasswordHasher
	emailSender      EmailSender
	config           *domain.AuthConfig
}

// NewSignInUseCase creates a new sign in use case
func NewSignInUseCase(
	userRepo UserRepository,
	accountRepo AccountRepository,
	sessionRepo SessionRepository,
	verificationRepo VerificationRepository,
	passwordHasher PasswordHasher,
	emailSender EmailSender,
	config *domain.AuthConfig,
) SignInUseCase {
	return &signInUseCase{
		userRepo:         userRepo,
		accountRepo:      accountRepo,
		sessionRepo:      sessionRepo,
		verificationRepo: verificationRepo,
		passwordHasher:   passwordHasher,
		emailSender:      emailSender,
		config:           config,
	}
}

// SignInEmail authenticates a user with email and password
func (uc *signInUseCase) SignInEmail(ctx context.Context, input *domain.SignInEmailInput) (*domain.SignInEmailOutput, error) {
	// Find user
	user, err := uc.userRepo.FindByEmail(ctx, input.Email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// Check email verification if required
	if uc.config.RequireEmailVerification && !user.EmailVerified {
		// Send verification email
		if uc.emailSender != nil {
			token := GenerateToken()
			verification := &domain.Verification{
				ID:         uuid.New().String(),
				Identifier: user.Email,
				Value:      token,
				ExpiresAt:  time.Now().Add(uc.config.VerificationTokenExpiry),
				CreatedAt:  time.Now(),
			}

			uc.verificationRepo.Create(ctx, verification)
			url := uc.config.BaseURL + "/auth/verify-email?token=" + token
			uc.emailSender.SendVerificationEmail(ctx, user.Email, token, url)
		}
		return nil, domain.ErrEmailNotVerified
	}

	// Find account
	account, err := uc.accountRepo.FindByUserIDAndProvider(ctx, user.ID, "credential")
	if err != nil || account.Password == nil {
		return nil, domain.ErrInvalidCredentials
	}

	// Verify password
	if !uc.passwordHasher.Verify(input.Password, *account.Password) {
		return nil, domain.ErrInvalidCredentials
	}

	// Create session
	expiresIn := uc.config.SessionExpiresIn
	if input.RememberMe {
		expiresIn = 30 * 24 * time.Hour // 30 days
	}

	session, err := uc.createSessionWithExpiry(ctx, user.ID, expiresIn, input.IPAddress, input.UserAgent)
	if err != nil {
		return nil, err
	}

	return &domain.SignInEmailOutput{
		User:    user,
		Session: session,
	}, nil
}

// createSessionWithExpiry creates a session with specified expiry
func (uc *signInUseCase) createSessionWithExpiry(ctx context.Context, userID string, expiresIn time.Duration, ipAddress, userAgent *string) (*domain.Session, error) {
	session := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     GenerateToken(),
		ExpiresAt: time.Now().Add(expiresIn),
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
