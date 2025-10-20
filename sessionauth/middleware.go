package sessionauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/domain"
)

// Middleware provides session-based authentication middleware
type Middleware struct {
	sessionRepo domain.SessionRepository
	userRepo    domain.UserRepository
	cookieName  string
}

// NewMiddleware creates a new session authentication middleware
func NewMiddleware(
	sessionRepo domain.SessionRepository,
	userRepo domain.UserRepository,
) *Middleware {
	return &Middleware{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		cookieName:  "go-better-auth.session",
	}
}

// WithCookieName sets a custom cookie name for session tokens
func (m *Middleware) WithCookieName(name string) *Middleware {
	m.cookieName = name
	return m
}

// Handler wraps an http.Handler with session authentication
// It extracts the session token from cookie or Authorization header,
// validates it, and attaches the authenticated user to the request context
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Try to extract session token
		token, err := m.extractToken(r)
		if err != nil || token == "" {
			// No valid token found - allow the request to continue
			// Handlers can check if user is authenticated using GetUser(r.Context())
			next.ServeHTTP(w, r)
			return
		}

		// Validate session and get user
		session, user, err := m.validateSession(ctx, token)
		if err != nil || session == nil || user == nil {
			// Session is invalid or expired - allow the request to continue
			// Handlers can check if user is authenticated using GetUser(r.Context())
			next.ServeHTTP(w, r)
			return
		}

		// Attach user and session to context
		ctx = context.WithValue(ctx, userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, session)

		// Continue with authenticated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HandlerFunc wraps an http.HandlerFunc with session authentication
func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Handler(http.HandlerFunc(next)).ServeHTTP(w, r)
	}
}

// Require returns a middleware that requires authentication
// If no valid session is found, it responds with 401 Unauthorized
func (m *Middleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check if user is already authenticated by the Handler middleware
		user := GetUser(ctx)
		if user != nil {
			// User is authenticated, continue
			next.ServeHTTP(w, r)
			return
		}

		// Try to extract session token
		token, err := m.extractToken(r)
		if err != nil || token == "" {
			respondUnauthorized(w)
			return
		}

		// Validate session and get user
		session, user, err := m.validateSession(ctx, token)
		if err != nil || session == nil || user == nil {
			respondUnauthorized(w)
			return
		}

		// Attach user and session to context
		ctx = context.WithValue(ctx, userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, session)

		// Continue with authenticated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireFunc wraps an http.HandlerFunc requiring authentication
func (m *Middleware) RequireFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Require(http.HandlerFunc(next)).ServeHTTP(w, r)
	}
}

// extractToken extracts the session token from the request
// It checks (in order):
// 1. Authorization header with Bearer scheme
// 2. Cookie with configured cookie name
func (m *Middleware) extractToken(r *http.Request) (string, error) {
	// Check Authorization header first (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		const bearerPrefix = "Bearer "
		if strings.HasPrefix(authHeader, bearerPrefix) {
			token := strings.TrimPrefix(authHeader, bearerPrefix)
			return strings.TrimSpace(token), nil
		}
	}

	// Check session cookie
	cookie, err := r.Cookie(m.cookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	return "", nil
}

// validateSession validates the session token and retrieves the associated user
func (m *Middleware) validateSession(ctx context.Context, token string) (*domain.Session, *domain.User, error) {
	// Find session by token
	session, err := m.sessionRepo.FindByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	if session == nil {
		return nil, nil, domain.ErrSessionNotFound
	}

	// Check if session is expired
	if session.ExpiresAt.Before(getCurrentTime()) {
		// Optionally delete expired session
		_ = m.sessionRepo.DeleteByToken(ctx, token)
		return nil, nil, domain.ErrSessionExpired
	}

	// Get the user associated with the session
	user, err := m.userRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, err
	}

	if user == nil {
		return nil, nil, domain.ErrUserNotFound
	}

	return session, user, nil
}

// respondUnauthorized responds with a 401 Unauthorized error
func respondUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"unauthorized","message":"Authentication required"}`))
}
