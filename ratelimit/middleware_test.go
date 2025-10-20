package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/m-t-a97/go-better-auth/domain"
)

func TestMiddlewareHandler(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	middleware := NewMiddleware(limiter, domain.StrategyIP, 2, time.Minute)

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Test first request - should succeed
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:8080"
	w1 := httptest.NewRecorder()

	middleware.Handler(handler).ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "2", w1.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "1", w1.Header().Get("X-RateLimit-Remaining"))

	// Test second request - should succeed
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "127.0.0.1:8080"
	w2 := httptest.NewRecorder()

	middleware.Handler(handler).ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "0", w2.Header().Get("X-RateLimit-Remaining"))

	// Test third request - should be rate limited
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "127.0.0.1:8080"
	w3 := httptest.NewRecorder()

	middleware.Handler(handler).ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusTooManyRequests, w3.Code)
	assert.NotEmpty(t, w3.Header().Get("Retry-After"))
}

func TestMiddlewareStrategyIP(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	middleware := NewMiddleware(limiter, domain.StrategyIP, 1, time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// IP 1: First request succeeds
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "192.168.1.1:8080"
	w1 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// IP 1: Second request fails (rate limited)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.1:8080"
	w2 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)

	// IP 2: Request succeeds (different IP)
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "192.168.1.2:8080"
	w3 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)
}

func TestMiddlewareStrategyUserID(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	middleware := NewMiddleware(limiter, domain.StrategyUserID, 1, time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	user := &domain.User{
		ID:    "user:123",
		Email: "test@example.com",
	}

	// Request with user in context
	req1 := httptest.NewRequest("GET", "/", nil)
	ctx1 := context.WithValue(req1.Context(), "user", user)
	req1 = req1.WithContext(ctx1)
	w1 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second request from same user should fail
	req2 := httptest.NewRequest("GET", "/", nil)
	ctx2 := context.WithValue(req2.Context(), "user", user)
	req2 = req2.WithContext(ctx2)
	w2 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
}

func TestMiddlewareRateLimitHeaders(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	middleware := NewMiddleware(limiter, domain.StrategyIP, 5, time.Hour)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()

	middleware.Handler(handler).ServeHTTP(w, req)

	// Check headers
	assert.Equal(t, "5", w.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "4", w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
}

func TestMiddlewareRetryAfterHeader(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	middleware := NewMiddleware(limiter, domain.StrategyIP, 1, time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Fill the limit
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:8080"
	w1 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w1, req1)

	// Try another request
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "127.0.0.1:8080"
	w2 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	assert.NotEmpty(t, w2.Header().Get("Retry-After"))

	retryAfter := w2.Header().Get("Retry-After")
	assert.NotEqual(t, "0", retryAfter)
}

func TestEndpointMiddleware(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	middleware := NewMiddleware(limiter, domain.StrategyIP, 100, time.Hour)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create endpoint-specific middleware with lower limit
	endpointMiddleware := middleware.EndpointMiddleware(2, time.Minute)

	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:8080"
	w1 := httptest.NewRecorder()
	endpointMiddleware(handler).ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "127.0.0.1:8080"
	w2 := httptest.NewRecorder()
	endpointMiddleware(handler).ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	// Third request should be limited
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "127.0.0.1:8080"
	w3 := httptest.NewRecorder()
	endpointMiddleware(handler).ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusTooManyRequests, w3.Code)
}

func TestXForwardedForHeader(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	middleware := NewMiddleware(limiter, domain.StrategyIP, 1, time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
	w1 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second request with same forwarded IP should fail
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
	w2 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
}

func TestXRealIPHeader(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	middleware := NewMiddleware(limiter, domain.StrategyIP, 1, time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-Real-IP", "10.0.0.1")
	w1 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second request with same real IP should fail
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Real-IP", "10.0.0.1")
	w2 := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
}
