package sessionauth

import (
	"context"
	"net/http"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/usecase"
)

const (
	// SessionCookieName is the default name of the session cookie
	SessionCookieName = "_session"
	// SessionContextKey is the context key for storing the session
	SessionContextKey = "session"
	// UserContextKey is the context key for storing the user
	UserContextKey = "user"
)

// Manager handles session validation and cookie management
type Manager struct {
	sessionRepo usecase.SessionRepository
	userRepo    usecase.UserRepository
	cookieName  string
	sameSite    http.SameSite
	secure      bool // Should be true in production (HTTPS)
	httpOnly    bool
	path        string
}

// ManagerConfig holds configuration for the session manager
type ManagerConfig struct {
	CookieName string
	Secure     bool
	Path       string
}

// NewManager creates a new session manager
func NewManager(sessionRepo usecase.SessionRepository, userRepo usecase.UserRepository, config *ManagerConfig) *Manager {
	if config == nil {
		config = &ManagerConfig{}
	}

	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = SessionCookieName
	}

	path := config.Path
	if path == "" {
		path = "/"
	}

	return &Manager{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		cookieName:  cookieName,
		sameSite:    http.SameSiteLaxMode,
		secure:      config.Secure,
		httpOnly:    true,
		path:        path,
	}
}

// ValidateSession validates a session token and returns the session and user
func (m *Manager) ValidateSession(ctx context.Context, token string) (*domain.Session, *domain.User, error) {
	if token == "" {
		return nil, nil, domain.ErrSessionNotFound
	}

	// Find session by token
	session, err := m.sessionRepo.FindByToken(ctx, token)
	if err != nil {
		return nil, nil, domain.ErrSessionNotFound
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		// Delete expired session
		_ = m.sessionRepo.DeleteByToken(ctx, token)
		return nil, nil, domain.ErrSessionExpired
	}

	// Get user associated with the session
	user, err := m.userRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, domain.ErrUserNotFound
	}

	return session, user, nil
}

// GetSessionCookie retrieves the session token from the request cookies
func (m *Manager) GetSessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", domain.ErrSessionNotFound
		}
		return "", err
	}
	return cookie.Value, nil
}

// SetSessionCookie sets the session cookie on the response
func (m *Manager) SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     m.path,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: m.httpOnly,
		Secure:   m.secure,
		SameSite: m.sameSite,
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie removes the session cookie from the response
func (m *Manager) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     m.path,
		MaxAge:   -1,
		HttpOnly: m.httpOnly,
		Secure:   m.secure,
		SameSite: m.sameSite,
	}
	http.SetCookie(w, cookie)
}
