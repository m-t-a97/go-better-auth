package auth

import (
	"fmt"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/user"
)

// UpdateUserRequest contains the request data for updating a user
type UpdateUserRequest struct {
	UserID string
	Name   *string
	Image  *string
}

// UpdateUserResponse contains the response data for updating a user
type UpdateUserResponse struct {
	User *user.User
}

// UpdateUser is the use case for updating a user's profile
func (s *Service) UpdateUser(req *UpdateUserRequest) (*UpdateUserResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("update user request cannot be nil")
	}

	// Validate request
	if req.UserID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	// Check if user exists
	existingUser, err := s.userRepo.FindByID(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Create update request for validation
	updateReq := &user.UpdateUserRequest{
		Name:  req.Name,
		Image: req.Image,
	}

	// Validate update request
	if err := user.ValidateUpdateUserRequest(updateReq); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Update fields if provided
	if req.Name != nil && *req.Name != "" {
		existingUser.Name = *req.Name
	}

	if req.Image != nil {
		existingUser.Image = req.Image
	}

	// Update timestamp
	existingUser.UpdatedAt = time.Now()

	// Save updated user
	if err := s.userRepo.Update(existingUser); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &UpdateUserResponse{
		User: existingUser,
	}, nil
}
