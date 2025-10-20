package usecase

import (
	"context"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// sessionUseCase handles session management business logic
type sessionUseCase struct {
	sessionRepo SessionRepository
	userRepo    UserRepository
	config      *domain.AuthConfig
}

// NewSessionUseCase creates a new session use case
func NewSessionUseCase(
	sessionRepo SessionRepository,
	userRepo UserRepository,
	config *domain.AuthConfig,
) SessionUseCase {
	return &sessionUseCase{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		config:      config,
	}
}

// GetSession retrieves a session by token
func (uc *sessionUseCase) GetSession(ctx context.Context, token string) (*domain.Session, *domain.User, error) {
	session, err := uc.sessionRepo.FindByToken(ctx, token)
	if err != nil {
		return nil, nil, domain.ErrInvalidToken
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		uc.sessionRepo.Delete(ctx, session.ID)
		return nil, nil, domain.ErrSessionExpired
	}

	// Get user
	user, err := uc.userRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, domain.ErrUserNotFound
	}

	return session, user, nil
}

// RefreshSession extends the expiration time of a session
func (uc *sessionUseCase) RefreshSession(ctx context.Context, input *domain.RefreshSessionInput) (*domain.RefreshSessionOutput, error) {
	session, err := uc.sessionRepo.FindByToken(ctx, input.Token)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		uc.sessionRepo.Delete(ctx, session.ID)
		return nil, domain.ErrSessionExpired
	}

	// Extend session expiration by the configured duration
	session.ExpiresAt = time.Now().Add(uc.config.SessionExpiresIn)
	session.UpdatedAt = time.Now()

	if err := uc.sessionRepo.Update(ctx, session); err != nil {
		return nil, err
	}

	// Get user
	user, err := uc.userRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	return &domain.RefreshSessionOutput{
		Session: session,
		User:    user,
	}, nil
}

// CleanExpiredSessions removes expired sessions from the database
func (uc *sessionUseCase) CleanExpiredSessions(ctx context.Context) error {
	return uc.sessionRepo.DeleteExpired(ctx)
}

// SignOut deletes a session
func (uc *sessionUseCase) SignOut(ctx context.Context, token string) error {
	return uc.sessionRepo.DeleteByToken(ctx, token)
}
