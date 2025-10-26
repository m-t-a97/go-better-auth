package auth

import (
	"fmt"

	"github.com/m-t-a97/go-better-auth/domain/user"
)

// GetMeRequest contains the request data for getting user information
type GetMeRequest struct {
	UserID string
}

// GetMeResponse contains the response data for getting user information
type GetMeResponse struct {
	User *user.User
}

// GetMe is the use case for retrieving a user's information
func (s *Service) GetMe(req *GetMeRequest) (*GetMeResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("get me request cannot be nil")
	}

	if req.UserID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	// Find user by ID
	userFound, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if userFound == nil {
		return nil, fmt.Errorf("user not found")
	}

	return &GetMeResponse{
		User: userFound,
	}, nil
}
