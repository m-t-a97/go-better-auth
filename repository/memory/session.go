package memory

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/m-t-a97/go-better-auth/domain/session"
)

// SessionRepository implements an in-memory session repository
type SessionRepository struct {
	mu       sync.RWMutex
	sessions map[string]*session.Session
}

// NewSessionRepository creates a new in-memory session repository
func NewSessionRepository() *SessionRepository {
	return &SessionRepository{
		sessions: make(map[string]*session.Session),
	}
}

// Create creates a new session
func (r *SessionRepository) Create(s *session.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if s == nil {
		return fmt.Errorf("session cannot be nil")
	}

	// Generate ID if not set
	if s.ID == "" {
		s.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	s.CreatedAt = now
	s.UpdatedAt = now

	r.sessions[s.ID] = s
	return nil
}

// FindByID retrieves a session by ID
func (r *SessionRepository) FindByID(id string) (*session.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if s, ok := r.sessions[id]; ok {
		return s, nil
	}

	return nil, fmt.Errorf("session not found")
}

// FindByToken retrieves a session by token
func (r *SessionRepository) FindByToken(token string) (*session.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, s := range r.sessions {
		if s.Token == token {
			return s, nil
		}
	}

	return nil, fmt.Errorf("session not found")
}

// FindByUserID retrieves all sessions for a user
func (r *SessionRepository) FindByUserID(userID string) ([]*session.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var sessions []*session.Session
	for _, s := range r.sessions {
		if s.UserID == userID {
			sessions = append(sessions, s)
		}
	}

	return sessions, nil
}

// Update updates an existing session
func (r *SessionRepository) Update(s *session.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if s == nil {
		return fmt.Errorf("session cannot be nil")
	}

	if _, ok := r.sessions[s.ID]; !ok {
		return fmt.Errorf("session not found")
	}

	s.UpdatedAt = time.Now()
	r.sessions[s.ID] = s
	return nil
}

// Delete deletes a session by ID
func (r *SessionRepository) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.sessions[id]; !ok {
		return fmt.Errorf("session not found")
	}

	delete(r.sessions, id)
	return nil
}

// DeleteByUserID deletes all sessions for a user
func (r *SessionRepository) DeleteByUserID(userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, s := range r.sessions {
		if s.UserID == userID {
			delete(r.sessions, id)
		}
	}

	return nil
}

// DeleteExpired deletes all expired sessions
func (r *SessionRepository) DeleteExpired() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for id, s := range r.sessions {
		if s.ExpiresAt.Before(now) {
			delete(r.sessions, id)
		}
	}

	return nil
}

// Count returns the total number of sessions
func (r *SessionRepository) Count() (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.sessions), nil
}

// ExistsByID checks if a session exists by ID
func (r *SessionRepository) ExistsByID(id string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.sessions[id]
	return ok, nil
}

// ExistsByToken checks if a session exists by token
func (r *SessionRepository) ExistsByToken(token string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, s := range r.sessions {
		if s.Token == token {
			return true, nil
		}
	}

	return false, nil
}
