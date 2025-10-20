package csrf

import (
	"net/http"

	"github.com/m-t-a97/go-better-auth/domain"
)

// Middleware handles CSRF token validation for state-changing requests
type Middleware struct {
	manager *Manager
}

// NewMiddleware creates a new CSRF middleware
func NewMiddleware(manager *Manager) *Middleware {
	return &Middleware{manager: manager}
}

// Handler wraps an http.Handler with CSRF validation
// GET, HEAD, and OPTIONS requests are exempt from CSRF validation
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF validation for safe methods
		if isSafeMethod(r.Method) {
			// Generate and set CSRF token for safe requests
			token, secret, err := m.manager.GenerateToken()
			if err == nil {
				m.manager.SetCSRFCookie(w, secret)
				w.Header().Set("X-CSRF-Token", token)
			}
			next.ServeHTTP(w, r)
			return
		}

		// Validate CSRF token for state-changing requests
		if err := m.ValidateRequest(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// HandlerFunc wraps an http.HandlerFunc with CSRF validation
func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Handler(http.HandlerFunc(next)).ServeHTTP(w, r)
	}
}

// ValidateRequest validates the CSRF token in the request
func (m *Middleware) ValidateRequest(w http.ResponseWriter, r *http.Request) error {
	// Get CSRF token from request (header or form)
	token, err := GetCSRFToken(r)
	if err != nil {
		return domain.ErrCSRFTokenMissing
	}

	// Get CSRF secret from cookie
	secret, err := m.manager.GetCSRFCookie(r)
	if err != nil {
		return domain.ErrCSRFSecretMissing
	}

	// Validate token against secret
	isValid, err := m.manager.ValidateToken(token, secret)
	if err != nil {
		return err
	}

	if !isValid {
		return domain.ErrCSRFTokenInvalid
	}

	return nil
}

// GenerateTokenForResponse generates a new CSRF token and sets the cookie + header
// This should be called on every GET request to ensure clients have valid tokens
func (m *Middleware) GenerateTokenForResponse(w http.ResponseWriter) (string, error) {
	token, secret, err := m.manager.GenerateToken()
	if err != nil {
		return "", err
	}

	m.manager.SetCSRFCookie(w, secret)
	w.Header().Set("X-CSRF-Token", token)

	return token, nil
}

// isSafeMethod checks if the HTTP method is considered "safe" (doesn't modify state)
func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}
