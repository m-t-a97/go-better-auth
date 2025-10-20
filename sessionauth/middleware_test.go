package sessionauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// mockSessionRepository is a mock implementation of SessionRepository
type mockSessionRepository struct {
	sessions map[string]*domain.Session
}

func (m *mockSessionRepository) Create(ctx context.Context, session *domain.Session) error {
	m.sessions[session.Token] = session
	return nil
}

func (m *mockSessionRepository) FindByToken(ctx context.Context, token string) (*domain.Session, error) {
	return m.sessions[token], nil
}

func (m *mockSessionRepository) FindByUserID(ctx context.Context, userID string) ([]*domain.Session, error) {
	var sessions []*domain.Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			sessions = append(sessions, s)
		}
	}
	return sessions, nil
}

func (m *mockSessionRepository) Update(ctx context.Context, session *domain.Session) error {
	m.sessions[session.Token] = session
	return nil
}

func (m *mockSessionRepository) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockSessionRepository) DeleteByToken(ctx context.Context, token string) error {
	delete(m.sessions, token)
	return nil
}

func (m *mockSessionRepository) DeleteExpired(ctx context.Context) error {
	return nil
}

// mockUserRepository is a mock implementation of UserRepository
type mockUserRepository struct {
	users map[string]*domain.User
}

func (m *mockUserRepository) Create(ctx context.Context, user *domain.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	return m.users[id], nil
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (m *mockUserRepository) Update(ctx context.Context, user *domain.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) Delete(ctx context.Context, id string) error {
	delete(m.users, id)
	return nil
}

func newMockRepositories() (*mockSessionRepository, *mockUserRepository) {
	return &mockSessionRepository{sessions: make(map[string]*domain.Session)},
		&mockUserRepository{users: make(map[string]*domain.User)}
}

func TestMiddlewareHandlerWithCookie(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Create test user
	user := &domain.User{
		ID:    "user123",
		Name:  "Test User",
		Email: "test@example.com",
	}
	userRepo.users["user123"] = user

	// Create test session
	futureTime := time.Now().Add(24 * time.Hour)
	session := &domain.Session{
		ID:        "session123",
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: futureTime,
	}
	sessionRepo.sessions["token123"] = session

	// Test handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticatedUser := GetUser(r.Context())
		if authenticatedUser == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-User-ID", authenticatedUser.ID)
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with session cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "go-better-auth.session",
		Value: "token123",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	if w.Header().Get("X-User-ID") != "user123" {
		t.Errorf("Expected user ID user123, got %s", w.Header().Get("X-User-ID"))
	}
}

func TestMiddlewareHandlerWithBearerToken(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Create test user
	user := &domain.User{
		ID:    "user123",
		Name:  "Test User",
		Email: "test@example.com",
	}
	userRepo.users["user123"] = user

	// Create test session
	futureTime := time.Now().Add(24 * time.Hour)
	session := &domain.Session{
		ID:        "session123",
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: futureTime,
	}
	sessionRepo.sessions["token123"] = session

	// Test handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticatedUser := GetUser(r.Context())
		if authenticatedUser == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-User-ID", authenticatedUser.ID)
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with Bearer token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer token123")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	if w.Header().Get("X-User-ID") != "user123" {
		t.Errorf("Expected user ID user123, got %s", w.Header().Get("X-User-ID"))
	}
}

func TestMiddlewareHandlerNoToken(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Test handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticatedUser := GetUser(r.Context())
		if authenticatedUser == nil {
			w.WriteHeader(http.StatusOK) // Continue without user
			return
		}
		w.WriteHeader(http.StatusConflict)
	}))

	// Create request without token
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 (continue without user), got %d", w.Code)
	}
}

func TestMiddlewareHandlerExpiredSession(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Create test user
	user := &domain.User{
		ID:    "user123",
		Name:  "Test User",
		Email: "test@example.com",
	}
	userRepo.users["user123"] = user

	// Create expired session
	pastTime := time.Now().Add(-24 * time.Hour)
	session := &domain.Session{
		ID:        "session123",
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: pastTime,
	}
	sessionRepo.sessions["token123"] = session

	// Test handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticatedUser := GetUser(r.Context())
		if authenticatedUser == nil {
			w.WriteHeader(http.StatusOK) // Continue without user
			return
		}
		w.WriteHeader(http.StatusConflict)
	}))

	// Create request with expired session cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "go-better-auth.session",
		Value: "token123",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 (expired session treated as no auth), got %d", w.Code)
	}
}

func TestMiddlewareRequireWithValidSession(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Create test user
	user := &domain.User{
		ID:    "user123",
		Name:  "Test User",
		Email: "test@example.com",
	}
	userRepo.users["user123"] = user

	// Create test session
	futureTime := time.Now().Add(24 * time.Hour)
	session := &domain.Session{
		ID:        "session123",
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: futureTime,
	}
	sessionRepo.sessions["token123"] = session

	// Test handler
	handler := middleware.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticatedUser := GetUser(r.Context())
		if authenticatedUser == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-User-ID", authenticatedUser.ID)
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with session cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "go-better-auth.session",
		Value: "token123",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestMiddlewareRequireWithoutToken(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Test handler
	handler := middleware.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create request without token
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestMiddlewareRequireWithInvalidToken(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Test handler
	handler := middleware.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with invalid token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestGetUserFromContext(t *testing.T) {
	user := &domain.User{
		ID:    "user123",
		Name:  "Test User",
		Email: "test@example.com",
	}

	ctx := context.WithValue(context.Background(), userContextKey, user)
	retrievedUser := GetUser(ctx)

	if retrievedUser == nil {
		t.Fatal("Expected user, got nil")
	}

	if retrievedUser.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, retrievedUser.ID)
	}
}

func TestGetUserFromContextNil(t *testing.T) {
	ctx := context.Background()
	user := GetUser(ctx)

	if user != nil {
		t.Errorf("Expected nil, got %v", user)
	}
}

func TestIsAuthenticated(t *testing.T) {
	user := &domain.User{ID: "user123"}
	ctx := context.WithValue(context.Background(), userContextKey, user)

	if !IsAuthenticated(ctx) {
		t.Error("Expected IsAuthenticated to return true")
	}
}

func TestIsAuthenticatedFalse(t *testing.T) {
	ctx := context.Background()

	if IsAuthenticated(ctx) {
		t.Error("Expected IsAuthenticated to return false")
	}
}

func TestGetUserID(t *testing.T) {
	user := &domain.User{ID: "user123"}
	ctx := context.WithValue(context.Background(), userContextKey, user)

	userID := GetUserID(ctx)

	if userID != "user123" {
		t.Errorf("Expected user123, got %s", userID)
	}
}

func TestGetUserIDEmpty(t *testing.T) {
	ctx := context.Background()

	userID := GetUserID(ctx)

	if userID != "" {
		t.Errorf("Expected empty string, got %s", userID)
	}
}

func TestCustomCookieName(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo).WithCookieName("custom-session")

	// Create test user
	user := &domain.User{
		ID:    "user123",
		Name:  "Test User",
		Email: "test@example.com",
	}
	userRepo.users["user123"] = user

	// Create test session
	futureTime := time.Now().Add(24 * time.Hour)
	session := &domain.Session{
		ID:        "session123",
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: futureTime,
	}
	sessionRepo.sessions["token123"] = session

	// Test handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticatedUser := GetUser(r.Context())
		if authenticatedUser == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-User-ID", authenticatedUser.ID)
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with custom cookie name
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "custom-session",
		Value: "token123",
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestGetSession(t *testing.T) {
	session := &domain.Session{
		ID:     "session123",
		UserID: "user123",
		Token:  "token123",
	}

	ctx := context.WithValue(context.Background(), sessionContextKey, session)
	retrievedSession := GetSession(ctx)

	if retrievedSession == nil {
		t.Fatal("Expected session, got nil")
	}

	if retrievedSession.ID != session.ID {
		t.Errorf("Expected ID %s, got %s", session.ID, retrievedSession.ID)
	}
}

func TestHandlerFunc(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Create test user and session
	user := &domain.User{ID: "user123"}
	userRepo.users["user123"] = user

	futureTime := time.Now().Add(24 * time.Hour)
	session := &domain.Session{
		ID:        "session123",
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: futureTime,
	}
	sessionRepo.sessions["token123"] = session

	// Test handler func
	var called bool
	handlerFunc := middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if GetUser(r.Context()) == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "go-better-auth.session",
		Value: "token123",
	})

	w := httptest.NewRecorder()
	handlerFunc(w, req)

	if !called {
		t.Error("Handler function was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestRequireFunc(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Create test user and session
	user := &domain.User{ID: "user123"}
	userRepo.users["user123"] = user

	futureTime := time.Now().Add(24 * time.Hour)
	session := &domain.Session{
		ID:        "session123",
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: futureTime,
	}
	sessionRepo.sessions["token123"] = session

	// Test require func
	var called bool
	handlerFunc := middleware.RequireFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "go-better-auth.session",
		Value: "token123",
	})

	w := httptest.NewRecorder()
	handlerFunc(w, req)

	if !called {
		t.Error("Handler function was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestRequireFuncWithoutAuth(t *testing.T) {
	sessionRepo, userRepo := newMockRepositories()
	middleware := NewMiddleware(sessionRepo, userRepo)

	// Test require func without auth
	var called bool
	handlerFunc := middleware.RequireFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handlerFunc(w, req)

	if called {
		t.Error("Handler function should not have been called")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}
