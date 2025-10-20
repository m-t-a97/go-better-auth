package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// MockRateLimiter for testing rate limiting middleware
type MockRateLimiter struct {
	allowed   bool
	callCount int
}

func (m *MockRateLimiter) Allow(key string, limit int64, window time.Duration) (bool, int, error) {
	m.callCount++
	return m.allowed, 60, nil
}

func (m *MockRateLimiter) GetRemaining(key string, limit int64, window time.Duration) (int64, error) {
	return limit - int64(m.callCount), nil
}

func (m *MockRateLimiter) Reset(key string) error {
	return nil
}

func (m *MockRateLimiter) Close() error {
	return nil
}

// TestOAuthRateLimitHeaders verifies that rate limit headers are set on OAuth responses
func TestOAuthRateLimitHeaders(t *testing.T) {
	limiter := &MockRateLimiter{allowed: true}
	middleware := NewMiddleware(limiter, domain.StrategyIP, 100, 1*time.Minute)

	// Create a simple handler that just returns OK
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	// Wrap the handler with rate limiting middleware
	rateLimitedHandler := middleware.Handler(handler)

	// Create a test request
	req := httptest.NewRequest("GET", "/oauth/google", nil)
	w := httptest.NewRecorder()

	// Execute
	rateLimitedHandler.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify rate limit headers are set
	if w.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("Expected X-RateLimit-Limit header")
	}

	limitStr := w.Header().Get("X-RateLimit-Limit")
	if limitStr != "100" {
		t.Errorf("Expected X-RateLimit-Limit to be 100, got %s", limitStr)
	}

	if w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("Expected X-RateLimit-Remaining header")
	}

	if w.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("Expected X-RateLimit-Reset header")
	}
}

// TestOAuthRateLimitExceeded verifies that 429 is returned when rate limit is exceeded
func TestOAuthRateLimitExceeded(t *testing.T) {
	limiter := &MockRateLimiter{allowed: false}
	middleware := NewMiddleware(limiter, domain.StrategyIP, 10, 1*time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	rateLimitedHandler := middleware.Handler(handler)

	req := httptest.NewRequest("GET", "/oauth/github/callback", nil)
	w := httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(w, req)

	// Verify 429 Too Many Requests
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	// Verify Retry-After header is set
	if w.Header().Get("Retry-After") == "" {
		t.Error("Expected Retry-After header")
	}

	retryAfter := w.Header().Get("Retry-After")
	if retryAfter != "60" {
		t.Errorf("Expected Retry-After to be 60, got %s", retryAfter)
	}
}

// TestOAuthRateLimitByIP verifies rate limiting is applied by IP
func TestOAuthRateLimitByIP(t *testing.T) {
	limiter := &MockRateLimiter{allowed: true}
	middleware := NewMiddleware(limiter, domain.StrategyIP, 100, 1*time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitedHandler := middleware.Handler(handler)

	// Simulate request from specific IP
	req := httptest.NewRequest("GET", "/oauth/discord", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	w := httptest.NewRecorder()
	rateLimitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestOAuthRateLimitMultipleRequests verifies sequential requests work with rate limiting
func TestOAuthRateLimitMultipleRequests(t *testing.T) {
	limiter := &MockRateLimiter{allowed: true}
	middleware := NewMiddleware(limiter, domain.StrategyIP, 10, 1*time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitedHandler := middleware.Handler(handler)

	// Make multiple requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/oauth/test", nil)
		w := httptest.NewRecorder()

		rateLimitedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}

		remaining := w.Header().Get("X-RateLimit-Remaining")
		if remaining == "" {
			t.Errorf("Request %d: Expected X-RateLimit-Remaining header", i+1)
		}
	}
}

// TestOAuthRateLimitReset verifies reset time header is valid
func TestOAuthRateLimitReset(t *testing.T) {
	limiter := &MockRateLimiter{allowed: true}
	middleware := NewMiddleware(limiter, domain.StrategyIP, 100, 1*time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitedHandler := middleware.Handler(handler)

	req := httptest.NewRequest("GET", "/oauth/google", nil)
	w := httptest.NewRecorder()

	before := time.Now()
	rateLimitedHandler.ServeHTTP(w, req)
	after := time.Now()

	resetHeader := w.Header().Get("X-RateLimit-Reset")
	if resetHeader == "" {
		t.Fatal("Expected X-RateLimit-Reset header")
	}

	resetTime, err := strconv.ParseInt(resetHeader, 10, 64)
	if err != nil {
		t.Fatalf("Failed to parse X-RateLimit-Reset: %v", err)
	}

	resetTimestamp := time.Unix(resetTime, 0)

	// Reset time should be approximately 1 minute from now
	expectedMin := before.Add(59 * time.Second)
	expectedMax := after.Add(61 * time.Second)

	if resetTimestamp.Before(expectedMin) || resetTimestamp.After(expectedMax) {
		t.Errorf("X-RateLimit-Reset outside expected range. Got %v, expected between %v and %v", resetTimestamp, expectedMin, expectedMax)
	}
}
