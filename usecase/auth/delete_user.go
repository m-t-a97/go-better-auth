package auth

import (
	"context"
	"fmt"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/domain/user"
)

// userToDomain converts a domain/user.User to domain.User
func userToDomain(u *user.User) *domain.User {
	return &domain.User{
		ID:            u.ID,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Image:         u.Image,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

// DeleteUserRequest contains the request data for deleting a user
type DeleteUserRequest struct {
	UserID string
}

// DeleteUserResponse contains the response data for deleting a user
type DeleteUserResponse struct {
	Success bool
}

// DeleteUser is the use case for deleting a user and all related data
func (s *Service) DeleteUser(req *DeleteUserRequest) (*DeleteUserResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("delete user request cannot be nil")
	}

	// Validate request
	if req.UserID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	// Check if user exists
	user, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Call BeforeDelete hook if configured
	ctx := context.Background()
	if s.config != nil && s.config.User != nil && s.config.User.DeleteUser != nil && s.config.User.DeleteUser.BeforeDelete != nil {
		// Convert user entity to domain.User for the hook
		domainUser := userToDomain(user)
		if err := s.config.User.DeleteUser.BeforeDelete(ctx, domainUser); err != nil {
			return nil, fmt.Errorf("before delete hook failed: %w", err)
		}
	}

	// Delete all sessions for this user
	sessions, err := s.sessionRepo.FindByUserID(req.UserID)
	if err == nil {
		for _, session := range sessions {
			if err := s.sessionRepo.Delete(session.ID); err != nil {
				return nil, fmt.Errorf("failed to delete session: %w", err)
			}
		}
	}

	// Delete all accounts for this user (OAuth providers)
	accounts, err := s.accountRepo.FindByUserID(req.UserID)
	if err == nil {
		for _, account := range accounts {
			if err := s.accountRepo.Delete(account.ID); err != nil {
				return nil, fmt.Errorf("failed to delete account: %w", err)
			}
		}
	}

	// Note: Verification tokens are stored with the user's email or ID as identifier.
	// When a user deletes their account, these tokens become orphaned but won't be
	// actively used since the user no longer exists. They'll be cleaned up by
	// DeleteExpired when they expire.

	// Delete the user
	if err := s.userRepo.Delete(req.UserID); err != nil {
		return nil, fmt.Errorf("failed to delete user: %w", err)
	}

	// Call AfterDelete hook if configured
	if s.config != nil && s.config.User != nil && s.config.User.DeleteUser != nil && s.config.User.DeleteUser.AfterDelete != nil {
		// Convert user entity to domain.User for the hook
		domainUser := userToDomain(user)
		if err := s.config.User.DeleteUser.AfterDelete(ctx, domainUser); err != nil {
			return nil, fmt.Errorf("after delete hook failed: %w", err)
		}
	}

	return &DeleteUserResponse{
		Success: true,
	}, nil
}
