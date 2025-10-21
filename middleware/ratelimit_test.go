package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/storage"
	"github.com/m-t-a97/go-better-auth/usecase/ratelimit"
)

func TestRateLimitMiddleware_Disabled(t *testing.T) {
	config := &domain.Config{
		RateLimit: &domain.RateLimitOptions{
			Enabled: false,
		},
	}

	secondary := storage.NewMemorySecondaryStorage()
	limiter := ratelimit.NewLimiter(secondary)
	middleware := RateLimitMiddleware(config, limiter)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_AllowsRequests(t *testing.T) {
	config := &domain.Config{
		RateLimit: &domain.RateLimitOptions{
			Enabled: true,
			Window:  10,
			Max:     5,
		},
	}

	secondary := storage.NewMemorySecondaryStorage()
	limiter := ratelimit.NewLimiter(secondary)
	middleware := RateLimitMiddleware(config, limiter)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Make requests up to the limit
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200 on request %d, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimitMiddleware_BlocksExcessRequests(t *testing.T) {
	config := &domain.Config{
		RateLimit: &domain.RateLimitOptions{
			Enabled: true,
			Window:  10,
			Max:     3,
		},
	}

	secondary := storage.NewMemorySecondaryStorage()
	limiter := ratelimit.NewLimiter(secondary)
	middleware := RateLimitMiddleware(config, limiter)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Make requests up to the limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200 on request %d, got %d", i+1, w.Code)
		}
	}

	// Next request should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_CustomRules(t *testing.T) {
	config := &domain.Config{
		RateLimit: &domain.RateLimitOptions{
			Enabled: true,
			Window:  10,
			Max:     5,
			CustomRules: map[string]domain.RateLimitRule{
				"/api/auth/signin": {
					Window: 10,
					Max:    2,
				},
			},
		},
	}

	secondary := storage.NewMemorySecondaryStorage()
	limiter := ratelimit.NewLimiter(secondary)
	middleware := RateLimitMiddleware(config, limiter)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Make 2 requests to signin (should be allowed)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/api/auth/signin", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200 on request %d, got %d", i+1, w.Code)
		}
	}

	// Next signin request should be blocked
	req := httptest.NewRequest("POST", "/api/auth/signin", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_DifferentIPs(t *testing.T) {
	config := &domain.Config{
		RateLimit: &domain.RateLimitOptions{
			Enabled: true,
			Window:  10,
			Max:     2,
		},
	}

	secondary := storage.NewMemorySecondaryStorage()
	limiter := ratelimit.NewLimiter(secondary)
	middleware := RateLimitMiddleware(config, limiter)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Make 2 requests from IP 1
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200 for IP1 request %d, got %d", i+1, w.Code)
		}
	}

	// Next request from IP 1 should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429 for IP1, got %d", w.Code)
	}

	// But requests from IP 2 should still be allowed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200 for IP2 request %d, got %d", i+1, w.Code)
		}
	}
}

func TestGetClientIP_XForwardedFor(t *testing.T) {
	config := &domain.Config{}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1")

	ip := getClientIP(req, config)
	if ip != "203.0.113.1" {
		t.Errorf("expected IP 203.0.113.1, got %s", ip)
	}
}

func TestGetClientIP_XRealIP(t *testing.T) {
	config := &domain.Config{}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "203.0.113.1")

	ip := getClientIP(req, config)
	if ip != "203.0.113.1" {
		t.Errorf("expected IP 203.0.113.1, got %s", ip)
	}
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	config := &domain.Config{}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"

	ip := getClientIP(req, config)
	if ip != "203.0.113.1" {
		t.Errorf("expected IP 203.0.113.1, got %s", ip)
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"/api/auth/signin", "/api/auth/signin", true},
		{"/api/auth/signin", "/api/auth/signup", false},
		{"/api/auth/signin", "/api/auth/*", true},
		{"/api/auth/signin", "/api/*", true},
		{"/api/auth/signin", "/api/user/*", false},
	}

	for _, tt := range tests {
		got := matchPath(tt.path, tt.pattern)
		if got != tt.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
		}
	}
}

func TestRateLimitMiddleware_NilConfig(t *testing.T) {
	config := &domain.Config{
		RateLimit: nil,
	}

	secondary := storage.NewMemorySecondaryStorage()
	limiter := ratelimit.NewLimiter(secondary)
	middleware := RateLimitMiddleware(config, limiter)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}
