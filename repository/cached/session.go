package cached

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/storage"
)

// SessionRepository wraps a session repository with secondary storage caching
// It caches session lookups by token to reduce database load
type SessionRepository struct {
	primary   session.Repository
	secondary storage.SecondaryStorage
	logger    *slog.Logger
}

// NewSessionRepository creates a new cached session repository
func NewSessionRepository(
	primary session.Repository,
	secondary storage.SecondaryStorage,
) *SessionRepository {
	return &SessionRepository{
		primary:   primary,
		secondary: secondary,
		logger:    slog.Default(),
	}
}

// Create creates a new session and caches it
func (r *SessionRepository) Create(sess *session.Session) error {
	if err := r.primary.Create(sess); err != nil {
		return err
	}

	// Cache the session token -> session ID mapping
	if err := r.cacheSession(sess); err != nil {
		r.logger.Warn("failed to cache session",
			"session_id", sess.ID,
			"error", err,
		)
		// Don't fail the operation if caching fails
	}

	return nil
}

// FindByID retrieves a session by ID from primary storage
func (r *SessionRepository) FindByID(id string) (*session.Session, error) {
	return r.primary.FindByID(id)
}

// FindByToken retrieves a session by token, checking cache first
func (r *SessionRepository) FindByToken(token string) (*session.Session, error) {
	ctx := context.Background()

	// Try to get from cache first
	cacheKey := r.sessionTokenCacheKey(token)
	cached, err := r.secondary.Get(ctx, cacheKey)
	if err == nil && cached != nil {
		r.logger.Debug("session found in cache", "token", token)

		// Deserialize cached session
		var sess session.Session
		if cachedStr, ok := cached.(string); ok {
			if err := json.Unmarshal([]byte(cachedStr), &sess); err == nil {
				// Verify session is still valid
				if !sess.IsExpired() {
					return &sess, nil
				}
				// Session expired, remove from cache
				_ = r.secondary.Delete(ctx, cacheKey)
			}
		}
	}

	// Cache miss or error, get from primary storage
	r.logger.Debug("session not in cache, fetching from primary storage", "token", token)
	sess, err := r.primary.FindByToken(token)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if err := r.cacheSession(sess); err != nil {
		r.logger.Warn("failed to cache session after fetch",
			"session_id", sess.ID,
			"error", err,
		)
	}

	return sess, nil
}

// FindByUserID retrieves all sessions for a user from primary storage
func (r *SessionRepository) FindByUserID(userID string) ([]*session.Session, error) {
	return r.primary.FindByUserID(userID)
}

// Update updates an existing session and updates cache
func (r *SessionRepository) Update(sess *session.Session) error {
	if err := r.primary.Update(sess); err != nil {
		return err
	}

	// Update cache
	if err := r.cacheSession(sess); err != nil {
		r.logger.Warn("failed to update cached session",
			"session_id", sess.ID,
			"error", err,
		)
	}

	return nil
}

// Delete deletes a session by ID and removes from cache
func (r *SessionRepository) Delete(id string) error {
	// Get session first to invalidate cache by token
	sess, err := r.primary.FindByID(id)
	if err == nil && sess != nil {
		ctx := context.Background()
		cacheKey := r.sessionTokenCacheKey(sess.Token)
		if err := r.secondary.Delete(ctx, cacheKey); err != nil {
			r.logger.Warn("failed to delete cached session",
				"session_id", id,
				"error", err,
			)
		}
	}

	return r.primary.Delete(id)
}

// DeleteByUserID deletes all sessions for a user
func (r *SessionRepository) DeleteByUserID(userID string) error {
	// Get all sessions first to invalidate cache
	sessions, err := r.primary.FindByUserID(userID)
	if err == nil {
		ctx := context.Background()
		for _, sess := range sessions {
			cacheKey := r.sessionTokenCacheKey(sess.Token)
			if err := r.secondary.Delete(ctx, cacheKey); err != nil {
				r.logger.Warn("failed to delete cached session",
					"session_id", sess.ID,
					"error", err,
				)
			}
		}
	}

	return r.primary.DeleteByUserID(userID)
}

// DeleteExpired deletes all expired sessions
func (r *SessionRepository) DeleteExpired() error {
	// Note: We don't clean up cache here as it will expire naturally
	// Or could be cleaned up by a background job
	return r.primary.DeleteExpired()
}

// Count returns the total number of sessions
func (r *SessionRepository) Count() (int, error) {
	return r.primary.Count()
}

// ExistsByID checks if a session exists by ID
func (r *SessionRepository) ExistsByID(id string) (bool, error) {
	return r.primary.ExistsByID(id)
}

// ExistsByToken checks if a session exists by token, checking cache first
func (r *SessionRepository) ExistsByToken(token string) (bool, error) {
	ctx := context.Background()

	// Try cache first
	cacheKey := r.sessionTokenCacheKey(token)
	cached, err := r.secondary.Get(ctx, cacheKey)
	if err == nil && cached != nil {
		return true, nil
	}

	// Check primary storage
	return r.primary.ExistsByToken(token)
}

// cacheSession serializes and caches a session
func (r *SessionRepository) cacheSession(sess *session.Session) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}

	ctx := context.Background()
	cacheKey := r.sessionTokenCacheKey(sess.Token)

	// Serialize session
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Calculate TTL based on session expiration
	ttl := int(time.Until(sess.ExpiresAt).Seconds())
	if ttl <= 0 {
		// Session already expired, don't cache
		return nil
	}

	if err := r.secondary.Set(ctx, cacheKey, string(data), ttl); err != nil {
		return fmt.Errorf("failed to cache session: %w", err)
	}

	return nil
}

// sessionTokenCacheKey generates the cache key for a session token
func (r *SessionRepository) sessionTokenCacheKey(token string) string {
	return fmt.Sprintf("session:token:%s", token)
}
