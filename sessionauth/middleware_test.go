package sessionauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// Mock repositories for testing
type mockSessionRepo struct {
	sessions map[string]*domain.Session
}

func (m *mockSessionRepo) Create(ctx context.Context, session *domain.Session) error {
	m.sessions[session.Token] = session
	return nil
}

func (m *mockSessionRepo) FindByToken(ctx context.Context, token string) (*domain.Session, error) {
	session, ok := m.sessions[token]
	if !ok {
		return nil, domain.ErrSessionNotFound
	}
	return session, nil
}

func (m *mockSessionRepo) FindByUserID(ctx context.Context, userID string) ([]*domain.Session, error) {
	return nil, nil
}

func (m *mockSessionRepo) Update(ctx context.Context, session *domain.Session) error {
	m.sessions[session.Token] = session
	return nil
}

func (m *mockSessionRepo) Delete(ctx context.Context, id string) error {
	for token, session := range m.sessions {
		if session.ID == id {
			delete(m.sessions, token)
			return nil
		}
	}
	return domain.ErrSessionNotFound
}

func (m *mockSessionRepo) DeleteByToken(ctx context.Context, token string) error {
	delete(m.sessions, token)
	return nil
}

func (m *mockSessionRepo) DeleteExpired(ctx context.Context) error {
	return nil
}

type mockUserRepo struct {
	users map[string]*domain.User
}

func (m *mockUserRepo) Create(ctx context.Context, user *domain.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepo) FindByID(ctx context.Context, id string) (*domain.User, error) {
	user, ok := m.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (m *mockUserRepo) Update(ctx context.Context, user *domain.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepo) Delete(ctx context.Context, id string) error {
	delete(m.users, id)
	return nil
}

func TestMiddleware_ValidSession(t *testing.T) {
	// Setup
	sessionRepo := &mockSessionRepo{sessions: make(map[string]*domain.Session)}
	userRepo := &mockUserRepo{users: make(map[string]*domain.User)}

	user := &domain.User{
		ID:    "user123",
		Email: "test@example.com",
		Name:  "Test User",
	}
	userRepo.Create(context.Background(), user)

	session := &domain.Session{
		ID:        "session123",
		UserID:    user.ID,
		Token:     "valid-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sessionRepo.Create(context.Background(), session)

	manager := NewManager(sessionRepo, userRepo, nil)
	middleware := NewMiddleware(manager)

	// Create test handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify session and user are in context
		contextSession := GetSession(r)
		contextUser := GetUser(r)

		if contextSession == nil {
			t.Error("Expected session in context")
		}
		if contextUser == nil {
			t.Error("Expected user in context")
		}
		if contextSession.Token != "valid-token" {
			t.Errorf("Expected token 'valid-token', got '%s'", contextSession.Token)
		}
		if contextUser.Email != "test@example.com" {
			t.Errorf("Expected email 'test@example.com', got '%s'", contextUser.Email)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Create request with session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: "valid-token",
	})

	// Test
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestMiddleware_ExpiredSession(t *testing.T) {
	// Setup
	sessionRepo := &mockSessionRepo{sessions: make(map[string]*domain.Session)}
	userRepo := &mockUserRepo{users: make(map[string]*domain.User)}

	user := &domain.User{
		ID:    "user123",
		Email: "test@example.com",
		Name:  "Test User",
	}
	userRepo.Create(context.Background(), user)

	session := &domain.Session{
		ID:        "session123",
		UserID:    user.ID,
		Token:     "expired-token",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sessionRepo.Create(context.Background(), session)

	manager := NewManager(sessionRepo, nil, nil)
	middleware := NewMiddleware(manager)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for expired session")
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with expired session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: "expired-token",
	})

	// Test
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestMiddleware_NoSession(t *testing.T) {
	// Setup
	sessionRepo := &mockSessionRepo{sessions: make(map[string]*domain.Session)}
	userRepo := &mockUserRepo{users: make(map[string]*domain.User)}

	manager := NewManager(sessionRepo, userRepo, nil)
	middleware := NewMiddleware(manager)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called without session")
		w.WriteHeader(http.StatusOK)
	}))

	// Create request without session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	// Test
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestOptionalMiddleware_WithSession(t *testing.T) {
	// Setup
	sessionRepo := &mockSessionRepo{sessions: make(map[string]*domain.Session)}
	userRepo := &mockUserRepo{users: make(map[string]*domain.User)}

	user := &domain.User{
		ID:    "user123",
		Email: "test@example.com",
		Name:  "Test User",
	}
	userRepo.Create(context.Background(), user)

	session := &domain.Session{
		ID:        "session123",
		UserID:    user.ID,
		Token:     "valid-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sessionRepo.Create(context.Background(), session)

	manager := NewManager(sessionRepo, userRepo, nil)
	middleware := NewOptionalMiddleware(manager)

	// Create test handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Session should be in context
		contextUser := GetUser(r)
		if contextUser == nil {
			t.Error("Expected user in context for optional middleware with valid session")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Create request with session cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: "valid-token",
	})

	// Test
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestOptionalMiddleware_WithoutSession(t *testing.T) {
	// Setup
	sessionRepo := &mockSessionRepo{sessions: make(map[string]*domain.Session)}
	userRepo := &mockUserRepo{users: make(map[string]*domain.User)}

	manager := NewManager(sessionRepo, userRepo, nil)
	middleware := NewOptionalMiddleware(manager)

	// Create test handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Session should NOT be in context
		contextUser := GetUser(r)
		if contextUser != nil {
			t.Error("Expected no user in context for optional middleware without session")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Create request without session cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Test
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Assert - should succeed even without session
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestManager_SetAndGetSessionCookie(t *testing.T) {
	manager := NewManager(nil, nil, nil)

	// Create response recorder
	w := httptest.NewRecorder()

	// Set session cookie
	expiresAt := time.Now().Add(24 * time.Hour)
	manager.SetSessionCookie(w, "test-token", expiresAt)

	// Get cookies from response
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != SessionCookieName {
		t.Errorf("Expected cookie name '%s', got '%s'", SessionCookieName, cookie.Name)
	}
	if cookie.Value != "test-token" {
		t.Errorf("Expected cookie value 'test-token', got '%s'", cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Error("Expected HttpOnly flag to be true")
	}
}

func TestManager_ClearSessionCookie(t *testing.T) {
	manager := NewManager(nil, nil, nil)

	// Create response recorder
	w := httptest.NewRecorder()

	// Clear session cookie
	manager.ClearSessionCookie(w)

	// Get cookies from response
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.MaxAge != -1 {
		t.Errorf("Expected MaxAge -1, got %d", cookie.MaxAge)
	}
	if cookie.Value != "" {
		t.Errorf("Expected empty value, got '%s'", cookie.Value)
	}
}
