package auth

import (
	"fmt"

	"github.com/m-t-a97/go-better-auth/domain/user"
)

// GetProfileRequest contains the request data for getting user profile
type GetProfileRequest struct {
	UserID string
}

// GetProfileResponse contains the response data for getting user profile
type GetProfileResponse struct {
	User *user.User
}

// GetProfile is the use case for retrieving a user's profile information
func (s *Service) GetProfile(req *GetProfileRequest) (*GetProfileResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("get profile request cannot be nil")
	}

	if req.UserID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	// Find user by ID
	u, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	return &GetProfileResponse{
		User: u,
	}, nil
}
