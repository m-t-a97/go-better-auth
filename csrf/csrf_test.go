package csrf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

func TestManagerGenerateToken(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)

	token, secret, err := manager.GenerateToken()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token == "" {
		t.Error("token should not be empty")
	}

	if secret == "" {
		t.Error("secret should not be empty")
	}

	// Tokens should be unique
	token2, secret2, _ := manager.GenerateToken()
	if token == token2 || secret == secret2 {
		t.Error("tokens should be unique")
	}
}

func TestManagerValidateToken_Valid(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)

	token, secret, _ := manager.GenerateToken()

	isValid, err := manager.ValidateToken(token, secret)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !isValid {
		t.Error("token should be valid")
	}
}

func TestManagerValidateToken_InvalidToken(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)

	_, err := manager.ValidateToken("invalid", "secret")

	if err != domain.ErrCSRFTokenInvalid {
		t.Errorf("expected ErrCSRFTokenInvalid, got %v", err)
	}
}

func TestManagerValidateToken_EmptyToken(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)

	_, err := manager.ValidateToken("", "secret")

	if err != domain.ErrCSRFTokenMissing {
		t.Errorf("expected ErrCSRFTokenMissing, got %v", err)
	}
}

func TestManagerValidateToken_EmptySecret(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)

	_, err := manager.ValidateToken("token", "")

	if err != domain.ErrCSRFSecretMissing {
		t.Errorf("expected ErrCSRFSecretMissing, got %v", err)
	}
}

func TestManagerValidateToken_Expired(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, -1*time.Second, false) // Negative TTL = immediate expiration

	token, secret, _ := manager.GenerateToken()

	// Wait a bit to ensure expiration
	time.Sleep(10 * time.Millisecond)

	_, err := manager.ValidateToken(token, secret)

	if err != domain.ErrCSRFTokenInvalid {
		t.Errorf("expected ErrCSRFTokenInvalid, got %v", err)
	}
}

func TestManagerSetCSRFCookie(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)

	w := httptest.NewRecorder()
	secret := "test-secret"

	manager.SetCSRFCookie(w, secret)

	cookie := w.Result().Cookies()
	if len(cookie) == 0 {
		t.Fatal("cookie not set")
	}

	if cookie[0].Name != CSRFCookieName {
		t.Errorf("expected cookie name %s, got %s", CSRFCookieName, cookie[0].Name)
	}

	if cookie[0].Value != secret {
		t.Errorf("expected cookie value %s, got %s", secret, cookie[0].Value)
	}

	if !cookie[0].HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
}

func TestManagerGetCSRFCookie(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "test-secret"})

	secret, err := manager.GetCSRFCookie(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if secret != "test-secret" {
		t.Errorf("expected secret 'test-secret', got %s", secret)
	}
}

func TestGetCSRFTokenFromHeader(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set(CSRFHeaderName, "test-token")

	token, err := GetCSRFToken(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "test-token" {
		t.Errorf("expected token 'test-token', got %s", token)
	}
}

func TestGetCSRFTokenFromForm(t *testing.T) {
	body := strings.NewReader(CSRFFormField + "=test-token")
	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	token, err := GetCSRFToken(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "test-token" {
		t.Errorf("expected token 'test-token', got %s", token)
	}
}

func TestGetCSRFTokenMissing(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)

	_, err := GetCSRFToken(req)

	if err != domain.ErrCSRFTokenMissing {
		t.Errorf("expected ErrCSRFTokenMissing, got %v", err)
	}
}

func TestMiddlewareHandlerSafeMethods(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)
	middleware := NewMiddleware(manager)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200 for %s, got %d", method, w.Code)
		}

		// Check that CSRF token was generated
		token := w.Header().Get("X-CSRF-Token")
		if token == "" {
			t.Errorf("CSRF token should be generated for %s request", method)
		}
	}
}

func TestMiddlewareHandlerUnsafeMethodsValid(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)
	middleware := NewMiddleware(manager)

	// Generate a valid token
	token, secret, _ := manager.GenerateToken()

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(CSRFHeaderName, token)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: secret})

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestMiddlewareHandlerUnsafeMethodsInvalid(t *testing.T) {
	repo := NewInMemoryRepository()
	manager := NewManager(repo, 15*time.Minute, false)
	middleware := NewMiddleware(manager)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(CSRFHeaderName, "invalid-token")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "invalid-secret"})

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestHiddenInput(t *testing.T) {
	token := "test-token"
	html := HiddenInput(token)

	if !strings.Contains(html, token) {
		t.Error("token should be in HTML output")
	}

	if !strings.Contains(html, CSRFFormField) {
		t.Error("form field name should be in HTML output")
	}

	if !strings.Contains(html, "hidden") {
		t.Error("input should be hidden")
	}
}

func TestHTMLMetaTag(t *testing.T) {
	token := "test-token"
	html := HTMLMetaTag(token)

	if !strings.Contains(html, token) {
		t.Error("token should be in HTML output")
	}

	if !strings.Contains(html, "csrf-token") {
		t.Error("meta tag should contain csrf-token name")
	}
}

func TestInMemoryRepositoryCleanupExpired(t *testing.T) {
	repo := NewInMemoryRepository()

	// Store an expired token
	repo.StoreToken("expired-token", "secret", time.Now().Add(-1*time.Hour))

	// Store a valid token
	repo.StoreToken("valid-token", "secret", time.Now().Add(1*time.Hour))

	// Cleanup
	repo.CleanupExpired()

	// Expired token should be gone
	isValid, _ := repo.ValidateToken("expired-token", "secret")
	if isValid {
		t.Error("expired token should be deleted")
	}

	// Valid token should remain
	isValid, _ = repo.ValidateToken("valid-token", "secret")
	if !isValid {
		t.Error("valid token should still exist")
	}
}
