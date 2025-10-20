package sessionauth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/m-t-a97/go-better-auth/domain"
)

// Middleware handles session authentication for HTTP requests
type Middleware struct {
	manager  *Manager
	optional bool // If true, doesn't block requests without valid sessions
}

// NewMiddleware creates a new session authentication middleware
// By default, it requires valid sessions (optional=false)
func NewMiddleware(manager *Manager) *Middleware {
	return &Middleware{
		manager:  manager,
		optional: false,
	}
}

// NewOptionalMiddleware creates a session middleware that doesn't require authentication
// but will populate context with session/user if valid credentials are present
func NewOptionalMiddleware(manager *Manager) *Middleware {
	return &Middleware{
		manager:  manager,
		optional: true,
	}
}

// Handler wraps an http.Handler with session authentication
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get session token from cookie
		token, err := m.manager.GetSessionCookie(r)
		if err != nil {
			if m.optional {
				// For optional auth, continue without session
				next.ServeHTTP(w, r)
				return
			}
			respondUnauthorized(w, "No session found")
			return
		}

		// Validate session and get user
		session, user, err := m.manager.ValidateSession(r.Context(), token)
		if err != nil {
			if m.optional {
				// For optional auth, continue without session
				next.ServeHTTP(w, r)
				return
			}

			// Clear invalid session cookie
			m.manager.ClearSessionCookie(w)

			// Return appropriate error
			if err == domain.ErrSessionExpired {
				respondUnauthorized(w, "Session expired")
			} else {
				respondUnauthorized(w, "Invalid session")
			}
			return
		}

		// Add session and user to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, SessionContextKey, session)
		ctx = context.WithValue(ctx, UserContextKey, user)

		// Continue with enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HandlerFunc wraps an http.HandlerFunc with session authentication
func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Handler(http.HandlerFunc(next)).ServeHTTP(w, r)
	}
}

// Helper functions for extracting session and user from context

// GetSession retrieves the session from the request context
// Returns nil if no session is present
func GetSession(r *http.Request) *domain.Session {
	session, ok := r.Context().Value(SessionContextKey).(*domain.Session)
	if !ok {
		return nil
	}
	return session
}

// GetUser retrieves the user from the request context
// Returns nil if no user is present
func GetUser(r *http.Request) *domain.User {
	user, ok := r.Context().Value(UserContextKey).(*domain.User)
	if !ok {
		return nil
	}
	return user
}

// MustGetSession retrieves the session from context or panics
// Use this only in handlers protected by required authentication middleware
func MustGetSession(r *http.Request) *domain.Session {
	session := GetSession(r)
	if session == nil {
		panic("session not found in context - ensure authentication middleware is applied")
	}
	return session
}

// MustGetUser retrieves the user from context or panics
// Use this only in handlers protected by required authentication middleware
func MustGetUser(r *http.Request) *domain.User {
	user := GetUser(r)
	if user == nil {
		panic("user not found in context - ensure authentication middleware is applied")
	}
	return user
}

// respondUnauthorized sends a 401 Unauthorized response
func respondUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]interface{}{
		"error": map[string]string{
			"code":    "unauthorized",
			"message": message,
		},
	}
	json.NewEncoder(w).Encode(response)
}
