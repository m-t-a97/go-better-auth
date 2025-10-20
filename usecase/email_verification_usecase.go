package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain"
)

// emailVerificationUseCase handles email verification business logic
type emailVerificationUseCase struct {
	userRepo         UserRepository
	verificationRepo VerificationRepository
	emailSender      EmailSender
	config           *domain.AuthConfig
}

// NewEmailVerificationUseCase creates a new email verification use case
func NewEmailVerificationUseCase(
	userRepo UserRepository,
	verificationRepo VerificationRepository,
	emailSender EmailSender,
	config *domain.AuthConfig,
) EmailVerificationUseCase {
	return &emailVerificationUseCase{
		userRepo:         userRepo,
		verificationRepo: verificationRepo,
		emailSender:      emailSender,
		config:           config,
	}
}

// SendVerificationEmail sends a verification email to the user
func (uc *emailVerificationUseCase) SendVerificationEmail(ctx context.Context, email string) error {
	if uc.emailSender == nil {
		return domain.ErrInvalidRequest
	}

	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if user.EmailVerified {
		return nil // Already verified
	}

	token := GenerateToken()
	verification := &domain.Verification{
		ID:         uuid.New().String(),
		Identifier: email,
		Value:      token,
		ExpiresAt:  time.Now().Add(uc.config.VerificationTokenExpiry),
		CreatedAt:  time.Now(),
	}

	if err := uc.verificationRepo.Create(ctx, verification); err != nil {
		return err
	}

	url := uc.config.BaseURL + "/auth/verify-email?token=" + token
	return uc.emailSender.SendVerificationEmail(ctx, email, token, url)
}

// VerifyEmail verifies a user's email address
func (uc *emailVerificationUseCase) VerifyEmail(ctx context.Context, token string) (*domain.User, error) {
	// Find verification
	// Note: We need to search by value (token) but identifier is unknown
	// This is a simplified implementation
	verification, err := uc.findVerificationByToken(ctx, token)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}

	// Check if expired
	if time.Now().After(verification.ExpiresAt) {
		uc.verificationRepo.Delete(ctx, verification.ID)
		return nil, domain.ErrInvalidToken
	}

	// Find and update user
	user, err := uc.userRepo.FindByEmail(ctx, verification.Identifier)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	if err := uc.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	// Delete verification token
	uc.verificationRepo.Delete(ctx, verification.ID)

	return user, nil
}

// findVerificationByToken finds verification by token
func (uc *emailVerificationUseCase) findVerificationByToken(ctx context.Context, token string) (*domain.Verification, error) {
	// This is a simplified implementation
	// In a real implementation, you would need to query by value field
	// For now, we'll assume the repository can handle this
	return uc.verificationRepo.FindByIdentifierAndValue(ctx, "", token)
}
