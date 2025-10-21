package session

import (
	"fmt"
	"time"
)

// Session represents an active user session
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	Token     string
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateSessionRequest represents a request to create a new session
type CreateSessionRequest struct {
	UserID    string
	ExpiresAt time.Time
	Token     string
	IPAddress *string
	UserAgent *string
}

// ValidateCreateSessionRequest validates a create session request
func ValidateCreateSessionRequest(req *CreateSessionRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.UserID == "" {
		return fmt.Errorf("user_id cannot be empty")
	}

	if req.Token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if len(req.Token) < 16 {
		return fmt.Errorf("token is too short (min 16 characters)")
	}

	if len(req.Token) > 512 {
		return fmt.Errorf("token is too long (max 512 characters)")
	}

	if req.ExpiresAt.IsZero() {
		return fmt.Errorf("expiration time is required")
	}

	if req.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("expiration time must be in the future")
	}

	if req.IPAddress != nil && *req.IPAddress != "" {
		if len(*req.IPAddress) > 45 {
			return fmt.Errorf("IP address is too long (max 45 characters)")
		}
	}

	if req.UserAgent != nil && *req.UserAgent != "" {
		if len(*req.UserAgent) > 500 {
			return fmt.Errorf("user agent is too long (max 500 characters)")
		}
	}

	return nil
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Repository defines the interface for session data access
type Repository interface {
	// Create creates a new session
	Create(session *Session) error

	// FindByID retrieves a session by ID
	FindByID(id string) (*Session, error)

	// FindByToken retrieves a session by token
	FindByToken(token string) (*Session, error)

	// FindByUserID retrieves all sessions for a user
	FindByUserID(userID string) ([]*Session, error)

	// Update updates an existing session
	Update(session *Session) error

	// Delete deletes a session by ID
	Delete(id string) error

	// DeleteByUserID deletes all sessions for a user
	DeleteByUserID(userID string) error

	// DeleteExpired deletes all expired sessions
	DeleteExpired() error

	// Count returns the total number of sessions
	Count() (int, error)

	// ExistsByID checks if a session exists by ID
	ExistsByID(id string) (bool, error)

	// ExistsByToken checks if a session exists by token
	ExistsByToken(token string) (bool, error)
}
