package memory

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/m-t-a97/go-better-auth/domain/user"
)

// UserRepository implements an in-memory user repository
type UserRepository struct {
	mu    sync.RWMutex
	users map[string]*user.User
}

// NewUserRepository creates a new in-memory user repository
func NewUserRepository() *UserRepository {
	return &UserRepository{
		users: make(map[string]*user.User),
	}
}

// Create creates a new user
func (r *UserRepository) Create(u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if u == nil {
		return fmt.Errorf("user cannot be nil")
	}

	// Check if email already exists
	for _, existing := range r.users {
		if existing.Email == u.Email {
			return fmt.Errorf("user with email %s already exists", u.Email)
		}
	}

	// Generate ID if not set
	if u.ID == "" {
		u.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now

	r.users[u.ID] = u
	return nil
}

// FindByID retrieves a user by ID
func (r *UserRepository) FindByID(id string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if u, ok := r.users[id]; ok {
		return u, nil
	}

	return nil, fmt.Errorf("user not found")
}

// FindByEmail retrieves a user by email
func (r *UserRepository) FindByEmail(email string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}

	return nil, fmt.Errorf("user not found")
}

// Update updates an existing user
func (r *UserRepository) Update(u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if u == nil {
		return fmt.Errorf("user cannot be nil")
	}

	if _, ok := r.users[u.ID]; !ok {
		return fmt.Errorf("user not found")
	}

	u.UpdatedAt = time.Now()
	r.users[u.ID] = u
	return nil
}

// Delete deletes a user by ID
func (r *UserRepository) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.users[id]; !ok {
		return fmt.Errorf("user not found")
	}

	delete(r.users, id)
	return nil
}

// List lists users with pagination
func (r *UserRepository) List(limit int, offset int) ([]*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	if offset < 0 {
		offset = 0
	}

	var users []*user.User
	i := 0
	for _, u := range r.users {
		if i >= offset && i < offset+limit {
			users = append(users, u)
		}
		i++
	}

	return users, nil
}

// Count returns the total number of users
func (r *UserRepository) Count() (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.users), nil
}

// ExistsByEmail checks if a user exists by email
func (r *UserRepository) ExistsByEmail(email string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, u := range r.users {
		if u.Email == email {
			return true, nil
		}
	}

	return false, nil
}

// ExistsByID checks if a user exists by ID
func (r *UserRepository) ExistsByID(id string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.users[id]
	return ok, nil
}
