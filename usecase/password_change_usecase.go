package usecase

import (
	"context"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// passwordChangeUseCase handles password change business logic
type passwordChangeUseCase struct {
	userRepo       UserRepository
	accountRepo    AccountRepository
	sessionRepo    SessionRepository
	passwordHasher PasswordHasher
}

// NewPasswordChangeUseCase creates a new password change use case
func NewPasswordChangeUseCase(
	userRepo UserRepository,
	accountRepo AccountRepository,
	sessionRepo SessionRepository,
	passwordHasher PasswordHasher,
) PasswordChangeUseCase {
	return &passwordChangeUseCase{
		userRepo:       userRepo,
		accountRepo:    accountRepo,
		sessionRepo:    sessionRepo,
		passwordHasher: passwordHasher,
	}
}

// ChangePassword changes a user's password
func (uc *passwordChangeUseCase) ChangePassword(ctx context.Context, userID, currentPassword string, newPassword string, revokeOtherSessions bool) error {
	// Validate password policy
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}

	// Verify current password
	account, err := uc.accountRepo.FindByUserIDAndProvider(ctx, userID, "credential")
	if err != nil || account.Password == nil {
		return domain.ErrInvalidCredentials
	}

	if !uc.passwordHasher.Verify(currentPassword, *account.Password) {
		return domain.ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := uc.passwordHasher.Hash(newPassword)
	if err != nil {
		return err
	}

	// Update account
	account.Password = &hashedPassword
	account.UpdatedAt = time.Now()

	if err := uc.accountRepo.Update(ctx, account); err != nil {
		return err
	}

	// Revoke other sessions if requested
	if revokeOtherSessions {
		sessions, err := uc.sessionRepo.FindByUserID(ctx, userID)
		if err == nil {
			for _, session := range sessions {
				uc.sessionRepo.Delete(ctx, session.ID)
			}
		}
	}

	return nil
}
