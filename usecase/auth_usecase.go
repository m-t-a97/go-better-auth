package usecase

import (
	"context"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// AuthUseCase handles authentication business logic
type AuthUseCase struct {
	signUpUseCase            SignUpUseCase
	signInUseCase            SignInUseCase
	sessionUseCase           SessionUseCase
	emailVerificationUseCase EmailVerificationUseCase
	passwordResetUseCase     PasswordResetUseCase
	passwordChangeUseCase    PasswordChangeUseCase
}

// NewAuthUseCase creates a new authentication use case
func NewAuthUseCase(
	userRepo UserRepository,
	sessionRepo SessionRepository,
	accountRepo AccountRepository,
	verificationRepo VerificationRepository,
	passwordHasher PasswordHasher,
	emailSender EmailSender,
	config *domain.AuthConfig,
) *AuthUseCase {
	if config.SessionExpiresIn == 0 {
		config.SessionExpiresIn = 7 * 24 * time.Hour // 7 days default
	}
	if config.VerificationTokenExpiry == 0 {
		config.VerificationTokenExpiry = 24 * time.Hour // 24 hours default
	}
	return &AuthUseCase{
		signUpUseCase: NewSignUpUseCase(
			userRepo,
			accountRepo,
			verificationRepo,
			passwordHasher,
			emailSender,
			sessionRepo,
			config,
		),
		signInUseCase: NewSignInUseCase(
			userRepo,
			accountRepo,
			sessionRepo,
			verificationRepo,
			passwordHasher,
			emailSender,
			config,
		),
		sessionUseCase: NewSessionUseCase(
			sessionRepo,
			userRepo,
			config,
		),
		emailVerificationUseCase: NewEmailVerificationUseCase(
			userRepo,
			verificationRepo,
			emailSender,
			config,
		),
		passwordResetUseCase: NewPasswordResetUseCase(
			userRepo,
			accountRepo,
			verificationRepo,
			passwordHasher,
			emailSender,
			config,
		),
		passwordChangeUseCase: NewPasswordChangeUseCase(
			userRepo,
			accountRepo,
			sessionRepo,
			passwordHasher,
		),
	}
}

// SignUpEmail registers a new user with email and password
func (uc *AuthUseCase) SignUpEmail(ctx context.Context, input *domain.SignUpEmailInput) (*domain.SignUpEmailOutput, error) {
	return uc.signUpUseCase.SignUpEmail(ctx, input)
}

// SignInEmail authenticates a user with email and password
func (uc *AuthUseCase) SignInEmail(ctx context.Context, input *domain.SignInEmailInput) (*domain.SignInEmailOutput, error) {
	return uc.signInUseCase.SignInEmail(ctx, input)
}

// GetSession retrieves a session by token
func (uc *AuthUseCase) GetSession(ctx context.Context, token string) (*domain.Session, *domain.User, error) {
	return uc.sessionUseCase.GetSession(ctx, token)
}

// RefreshSession extends the expiration time of a session
func (uc *AuthUseCase) RefreshSession(ctx context.Context, input *domain.RefreshSessionInput) (*domain.RefreshSessionOutput, error) {
	return uc.sessionUseCase.RefreshSession(ctx, input)
}

// CleanExpiredSessions removes expired sessions from the database
func (uc *AuthUseCase) CleanExpiredSessions(ctx context.Context) error {
	return uc.sessionUseCase.CleanExpiredSessions(ctx)
}

// SignOut deletes a session
func (uc *AuthUseCase) SignOut(ctx context.Context, token string) error {
	return uc.sessionUseCase.SignOut(ctx, token)
}

// SendVerificationEmail sends a verification email to the user
func (uc *AuthUseCase) SendVerificationEmail(ctx context.Context, email string) error {
	return uc.emailVerificationUseCase.SendVerificationEmail(ctx, email)
}

// VerifyEmail verifies a user's email address
func (uc *AuthUseCase) VerifyEmail(ctx context.Context, token string) (*domain.User, error) {
	return uc.emailVerificationUseCase.VerifyEmail(ctx, token)
}

// RequestPasswordReset sends a password reset email
func (uc *AuthUseCase) RequestPasswordReset(ctx context.Context, email string) error {
	return uc.passwordResetUseCase.RequestPasswordReset(ctx, email)
}

// ResetPassword resets a user's password using a token
func (uc *AuthUseCase) ResetPassword(ctx context.Context, token, newPassword string) error {
	return uc.passwordResetUseCase.ResetPassword(ctx, token, newPassword)
}

// ChangePassword changes a user's password
func (uc *AuthUseCase) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string, revokeOtherSessions bool) error {
	return uc.passwordChangeUseCase.ChangePassword(ctx, userID, currentPassword, newPassword, revokeOtherSessions)
}
