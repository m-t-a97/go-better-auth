package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/m-t-a97/go-better-auth/internal/domain"
)

const (
	// CSRFTokenLength is the length of the CSRF token in bytes
	CSRFTokenLength = 32
	// CSRFSecretLength is the length of the CSRF secret in bytes
	CSRFSecretLength = 32
	// CSRFCookieName is the name of the CSRF secret cookie
	CSRFCookieName = "_csrf_secret"
	// CSRFHeaderName is the name of the CSRF token header
	CSRFHeaderName = "X-CSRF-Token"
	// CSRFFormField is the name of the CSRF token form field
	CSRFFormField = "_csrf"
)

// Manager handles CSRF token generation and validation
type Manager struct {
	repository domain.CSRFRepository
	tokenTTL   time.Duration
	sameSite   http.SameSite
	secure     bool // Should only be true in HTTPS
	httpOnly   bool
}

// NewManager creates a new CSRF manager
func NewManager(repository domain.CSRFRepository, tokenTTL time.Duration, secure bool) *Manager {
	return &Manager{
		repository: repository,
		tokenTTL:   tokenTTL,
		sameSite:   http.SameSite(2), // http.SameSiteLax = 2
		secure:     secure,
		httpOnly:   true,
	}
}

// GenerateToken generates a new CSRF token pair
// Returns (token, secret, error)
func (m *Manager) GenerateToken() (string, string, error) {
	// Generate random token
	tokenBytes := make([]byte, CSRFTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)

	// Generate random secret
	secretBytes := make([]byte, CSRFSecretLength)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", err
	}
	secret := hex.EncodeToString(secretBytes)

	// Store token and secret with TTL
	expiresAt := time.Now().Add(m.tokenTTL)
	if err := m.repository.StoreToken(token, secret, expiresAt); err != nil {
		return "", "", err
	}

	return token, secret, nil
}

// ValidateToken validates a CSRF token against the secret
func (m *Manager) ValidateToken(token, secret string) (bool, error) {
	if token == "" {
		return false, domain.ErrCSRFTokenMissing
	}
	if secret == "" {
		return false, domain.ErrCSRFSecretMissing
	}

	isValid, err := m.repository.ValidateToken(token, secret)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, domain.ErrCSRFMismatch
	}

	// Delete the token after successful validation (one-time use)
	_ = m.repository.DeleteToken(token)

	return true, nil
}

// SetCSRFCookie sets the CSRF secret cookie on the response
func (m *Manager) SetCSRFCookie(w http.ResponseWriter, secret string) {
	cookie := &http.Cookie{
		Name:     CSRFCookieName,
		Value:    secret,
		Path:     "/",
		MaxAge:   int(m.tokenTTL.Seconds()),
		HttpOnly: m.httpOnly,
		Secure:   m.secure,
		SameSite: m.sameSite,
	}
	http.SetCookie(w, cookie)
}

// GetCSRFCookie retrieves the CSRF secret from the request cookies
func (m *Manager) GetCSRFCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return "", domain.ErrCSRFSecretMissing
	}
	return cookie.Value, nil
}

// GetCSRFToken retrieves the CSRF token from the request
// Checks header first, then form data
func GetCSRFToken(r *http.Request) (string, error) {
	// Check header first
	if token := r.Header.Get(CSRFHeaderName); token != "" {
		return token, nil
	}

	// Check form data
	if token := r.FormValue(CSRFFormField); token != "" {
		return token, nil
	}

	return "", domain.ErrCSRFTokenMissing
}

// CleanupExpiredTokens removes all expired CSRF tokens
func (m *Manager) CleanupExpiredTokens() error {
	return m.repository.CleanupExpired()
}
