package middleware

import (
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// AuthMiddleware validates the session token and extracts the user ID from the request
// It expects the token in either:
// 1. Authorization header (Bearer <token>)
// 2. Cookie named "session" or custom cookie name
//
// On successful validation, it sets UserID and SessionToken in the request context
// If validation fails, it returns a 401 Unauthorized response
type AuthMiddleware struct {
	service    *auth.Service
	cookieName string
}

// NewAuthMiddleware creates a new auth middleware with default settings
func NewAuthMiddleware(svc *auth.Service) *AuthMiddleware {
	return &AuthMiddleware{
		service:    svc,
		cookieName: "session",
	}
}

// NewAuthMiddlewareWithCookie creates a new auth middleware with a custom cookie name
func NewAuthMiddlewareWithCookie(svc *auth.Service, cookieName string) *AuthMiddleware {
	return &AuthMiddleware{
		service:    svc,
		cookieName: cookieName,
	}
}

func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := m.extractToken(r)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Validate session
		resp, err := m.service.ValidateSession(&auth.ValidateSessionRequest{
			SessionToken: token,
		})
		if err != nil || !resp.Valid {
			http.Error(w, "unauthorized: invalid session", http.StatusUnauthorized)
			return
		}

		// Set user ID and session token in context
		ctx := SetUserID(r.Context(), resp.Session.UserID)
		ctx = SetSessionToken(ctx, token)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *AuthMiddleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Handler(next).ServeHTTP(w, r)
	}
}

// extractToken extracts the session token from the request
// It tries Authorization header first, then falls back to cookies
func (m *AuthMiddleware) extractToken(r *http.Request) (string, error) {
	// Try Authorization header first (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1], nil
		}
	}

	// Try cookie
	cookie, err := r.Cookie(m.cookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	return "", ErrMissingAuthToken
}

// OptionalAuthMiddleware is similar to AuthMiddleware but doesn't require authentication
// If a valid token is found, it sets UserID and SessionToken in context
// If not, it passes the request through without setting context values
type OptionalAuthMiddleware struct {
	service    *auth.Service
	cookieName string
}

// NewOptionalAuthMiddleware creates a new optional auth middleware with default settings
func NewOptionalAuthMiddleware(svc *auth.Service) *OptionalAuthMiddleware {
	return &OptionalAuthMiddleware{
		service:    svc,
		cookieName: "session",
	}
}

// NewOptionalAuthMiddlewareWithCookie creates a new optional auth middleware with a custom cookie name
func NewOptionalAuthMiddlewareWithCookie(svc *auth.Service, cookieName string) *OptionalAuthMiddleware {
	return &OptionalAuthMiddleware{
		service:    svc,
		cookieName: cookieName,
	}
}

// Handler returns an HTTP middleware function that can be used with net/http
func (m *OptionalAuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := m.extractToken(r)
		if err != nil {
			// No token provided, just pass through
			next.ServeHTTP(w, r)
			return
		}

		// Validate session
		resp, err := m.service.ValidateSession(&auth.ValidateSessionRequest{
			SessionToken: token,
		})
		if err != nil || !resp.Valid {
			// Invalid token, but don't fail - just pass through
			next.ServeHTTP(w, r)
			return
		}

		// Set user ID and session token in context
		ctx := SetUserID(r.Context(), resp.Session.UserID)
		ctx = SetSessionToken(ctx, token)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HandlerFunc returns an HTTP middleware function that works with http.HandlerFunc
func (m *OptionalAuthMiddleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Handler(next).ServeHTTP(w, r)
	}
}

// extractToken extracts the session token from the request
func (m *OptionalAuthMiddleware) extractToken(r *http.Request) (string, error) {
	// Try Authorization header first (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1], nil
		}
	}

	// Try cookie
	cookie, err := r.Cookie(m.cookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	return "", ErrMissingAuthToken
}
