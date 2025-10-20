package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/m-t-a97/go-better-auth/internal/domain"
)

// Middleware provides HTTP middleware for rate limiting
type Middleware struct {
	limiter  domain.RateLimiter
	strategy domain.RateLimitStrategy
	limit    int64
	window   time.Duration
}

// NewMiddleware creates a new rate limiting middleware
func NewMiddleware(limiter domain.RateLimiter, strategy domain.RateLimitStrategy, limit int64, window time.Duration) *Middleware {
	return &Middleware{
		limiter:  limiter,
		strategy: strategy,
		limit:    limit,
		window:   window,
	}
}

// Handler returns an HTTP middleware function
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := m.generateKey(r)
		allowed, retryAfter, err := m.limiter.Allow(key, m.limit, m.window)

		// Add rate limit headers
		remaining, _ := m.limiter.GetRemaining(key, m.limit, m.window)
		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(m.limit, 10))
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(m.window).Unix(), 10))

		if err != nil {
			// Log error but don't block the request
			// In production, you might want to handle this differently
			next.ServeHTTP(w, r)
			return
		}

		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			respondRateLimitExceeded(w, retryAfter)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// EndpointMiddleware creates middleware for a specific endpoint with custom limits
func (m *Middleware) EndpointMiddleware(limit int64, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := m.generateKey(r)
			allowed, retryAfter, err := m.limiter.Allow(key, limit, window)

			// Add rate limit headers
			remaining, _ := m.limiter.GetRemaining(key, limit, window)
			w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(limit, 10))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(window).Unix(), 10))

			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				respondRateLimitExceeded(w, retryAfter)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// generateKey generates a rate limiting key based on the strategy
func (m *Middleware) generateKey(r *http.Request) string {
	switch m.strategy {
	case domain.StrategyIP:
		return getIPAddress(r)

	case domain.StrategyUserID:
		// Try to get user ID from context (set by auth middleware)
		if user, ok := r.Context().Value("user").(*domain.User); ok {
			return "user:" + user.ID
		}
		// Fall back to IP if not authenticated
		return "user:anonymous:" + getIPAddress(r)

	case domain.StrategyAPIKey:
		// Get API key from header
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			apiKey := strings.TrimPrefix(auth, "Bearer ")
			return "api_key:" + hashKey(apiKey)
		}
		return "api_key:unknown:" + getIPAddress(r)

	case domain.StrategyIPAndEndpoint:
		ip := getIPAddress(r)
		endpoint := r.Method + ":" + r.RequestURI
		return ip + ":" + hashKey(endpoint)

	default:
		return getIPAddress(r)
	}
}

// Helper functions

func getIPAddress(r *http.Request) string {
	// Try X-Forwarded-For header first
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	// Try X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

func hashKey(key string) string {
	// Simple hash for API keys (in production, use proper hashing)
	hash := 0
	for _, c := range key {
		hash = ((hash << 5) - hash) + int(c)
	}
	return fmt.Sprintf("%x", hash)
}

func respondRateLimitExceeded(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)

	// Simple JSON encoding without external dependencies
	fmt.Fprintf(w, `{"error":{"code":"rate_limit_exceeded","message":"Too many requests. Please try again later"},"retryAfter":%d}`, retryAfter)
}

// PresetLimits defines common rate limiting presets
type PresetLimits struct {
	// Auth endpoints (sign-up, sign-in, password reset, etc.)
	Auth int64

	// MFA verification
	MFA int64

	// General API endpoints
	General int64

	// Sensitive operations (change password, reset password, etc.)
	Sensitive int64
}

// DefaultPresets returns default rate limiting presets
func DefaultPresets() PresetLimits {
	return PresetLimits{
		Auth:      5,   // 5 attempts per 15 minutes
		MFA:       3,   // 3 attempts per 5 minutes
		General:   100, // 100 requests per hour
		Sensitive: 3,   // 3 attempts per 30 minutes
	}
}
