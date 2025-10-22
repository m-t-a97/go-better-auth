package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/repository/memory"
	"github.com/m-t-a97/go-better-auth/usecase/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== Context Tests =====

func TestGetUserID_Success(t *testing.T) {
	ctx := SetUserID(context.Background(), "user-123")

	userID, err := GetUserID(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "user-123", userID)
}

func TestGetUserID_Missing(t *testing.T) {
	ctx := context.Background()

	userID, err := GetUserID(ctx)
	assert.Error(t, err)
	assert.Equal(t, "", userID)
	assert.Equal(t, "user ID not found in context", err.Error())
}

func TestGetUserID_Empty(t *testing.T) {
	ctx := SetUserID(context.Background(), "")

	userID, err := GetUserID(ctx)
	assert.Error(t, err)
	assert.Equal(t, "", userID)
	assert.Equal(t, "user ID is empty", err.Error())
}

func TestMustGetUserID_Success(t *testing.T) {
	ctx := SetUserID(context.Background(), "user-123")

	userID := MustGetUserID(ctx)
	assert.Equal(t, "user-123", userID)
}

func TestMustGetUserID_Panic(t *testing.T) {
	defer func() {
		r := recover()
		assert.NotNil(t, r)
		assert.Contains(t, r.(string), "user ID not found in context")
	}()

	ctx := context.Background()
	MustGetUserID(ctx)
}

func TestGetSessionToken_Success(t *testing.T) {
	ctx := SetSessionToken(context.Background(), "token-123")

	token, err := GetSessionToken(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "token-123", token)
}

func TestGetSessionToken_Missing(t *testing.T) {
	ctx := context.Background()

	token, err := GetSessionToken(ctx)
	assert.Error(t, err)
	assert.Equal(t, "", token)
	assert.Equal(t, "session token not found in context", err.Error())
}

// ===== AuthMiddleware Tests =====

func TestAuthMiddleware_ValidBearerToken(t *testing.T) {
	// Setup
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Create a user and sign in to get a session
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create middleware and protected handler
	middleware := NewAuthMiddleware(service)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetUserID(r.Context())
		assert.NoError(t, err)
		assert.Equal(t, signupResp.User.ID, userID)
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with Bearer token
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	middleware := NewAuthMiddleware(service)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized")
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	middleware := NewAuthMiddleware(service)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidBearerFormat(t *testing.T) {
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	middleware := NewAuthMiddleware(service)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "invalid-format")

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_CookieToken(t *testing.T) {
	// Setup
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Create a user and sign in to get a session
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create middleware with custom cookie name
	middleware := NewAuthMiddlewareWithCookie(service, "auth_token")
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetUserID(r.Context())
		assert.NoError(t, err)
		assert.Equal(t, signupResp.User.ID, userID)
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "auth_token",
		Value: token,
	})

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_HandlerFunc(t *testing.T) {
	// Setup
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Create a user and sign in
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create middleware
	middleware := NewAuthMiddleware(service)

	// Create handler with HandlerFunc
	var capturedUserID string
	handler := middleware.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, err := GetUserID(r.Context())
		assert.NoError(t, err)
		capturedUserID = uid
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, signupResp.User.ID, capturedUserID)
}

// ===== OptionalAuthMiddleware Tests =====

func TestOptionalAuthMiddleware_ValidToken(t *testing.T) {
	// Setup
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Create a user and sign in
	signupResp, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create optional middleware
	middleware := NewOptionalAuthMiddleware(service)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetUserID(r.Context())
		assert.NoError(t, err)
		assert.Equal(t, signupResp.User.ID, userID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOptionalAuthMiddleware_NoToken(t *testing.T) {
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	middleware := NewOptionalAuthMiddleware(service)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should be able to check if user ID exists without error
		_, err := GetUserID(r.Context())
		assert.Error(t, err) // UserID won't be present

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOptionalAuthMiddleware_InvalidToken(t *testing.T) {
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	middleware := NewOptionalAuthMiddleware(service)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should still be able to access without error
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ===== Integration Tests =====

func TestAuthMiddleware_SetSessionTokenInContext(t *testing.T) {
	// Setup
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Create a user and sign in
	_, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	token := signinResp.Session.Token

	// Create middleware
	middleware := NewAuthMiddleware(service)
	var capturedToken string
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionToken, err := GetSessionToken(r.Context())
		assert.NoError(t, err)
		capturedToken = sessionToken
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, token, capturedToken)
}

func TestAuthMiddleware_ExpiredSession(t *testing.T) {
	// Setup
	service := auth.NewService(
		&domain.Config{},
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)

	// Create a user and sign in
	_, err := service.SignUp(context.Background(), &auth.SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)

	signinResp, err := service.SignIn(context.Background(), &auth.SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	// Manually expire the session by waiting or skip this test
	// In a real test, you'd directly modify the session in the repository
	sess := signinResp.Session
	sess.ExpiresAt = time.Now().Add(-1 * time.Hour)

	token := signinResp.Session.Token

	// Create middleware
	middleware := NewAuthMiddleware(service)
	protectedHandler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	protectedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
