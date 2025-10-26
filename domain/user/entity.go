package user

import (
	"fmt"
	"net/mail"
	"time"
)

// User represents an authenticated user in the system
type User struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Image         *string   `json:"image"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Name  string
	Email string
	Image *string
}

// UpdateUserRequest represents a request to update an existing user
type UpdateUserRequest struct {
	Name  *string
	Image *string
}

// ValidateEmail validates an email address format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	if len(email) > 254 {
		return fmt.Errorf("email is too long (max 254 characters)")
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format: %w", err)
	}

	return nil
}

// ValidateCreateUserRequest validates a create user request
func ValidateCreateUserRequest(req *CreateUserRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	if len(req.Name) > 255 {
		return fmt.Errorf("name is too long (max 255 characters)")
	}

	if err := ValidateEmail(req.Email); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	if req.Image != nil && *req.Image != "" {
		if len(*req.Image) > 2000 {
			return fmt.Errorf("image URL is too long (max 2000 characters)")
		}
	}

	return nil
}

// ValidateUpdateUserRequest validates an update user request
func ValidateUpdateUserRequest(req *UpdateUserRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.Name != nil && *req.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	if req.Name != nil && len(*req.Name) > 255 {
		return fmt.Errorf("name is too long (max 255 characters)")
	}

	if req.Image != nil && *req.Image != "" {
		if len(*req.Image) > 2000 {
			return fmt.Errorf("image URL is too long (max 2000 characters)")
		}
	}

	return nil
}

// Repository defines the interface for user data access
type Repository interface {
	// Create creates a new user
	Create(user *User) error

	// FindByID retrieves a user by ID
	FindByID(id string) (*User, error)

	// FindByEmail retrieves a user by email
	FindByEmail(email string) (*User, error)

	// Update updates an existing user
	Update(user *User) error

	// Delete deletes a user by ID
	Delete(id string) error

	// List lists users with pagination
	List(limit int, offset int) ([]*User, error)

	// Count returns the total number of users
	Count() (int, error)

	// ExistsByEmail checks if a user exists by email
	ExistsByEmail(email string) (bool, error)

	// ExistsByID checks if a user exists by ID
	ExistsByID(id string) (bool, error)
}
