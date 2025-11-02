package middleware

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/usecase/ratelimit"
)

// RateLimitMiddleware creates a middleware that enforces rate limiting
func RateLimitMiddleware(config *domain.Config, limiter *ratelimit.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if rate limiting is enabled
			if config.RateLimit == nil || !config.RateLimit.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Get client IP
			ip := getClientIP(r, config)
			if ip == "" {
				slog.Warn("failed to get client IP for rate limiting")
				// Continue without rate limiting
				next.ServeHTTP(w, r)
				return
			}

			// Get rate limit configuration for this path
			window, max := getRateLimitConfig(r.URL.Path, config.RateLimit)

			// Get algorithm (default to fixed-window if not specified)
			algorithm := config.RateLimit.Algorithm
			if algorithm == "" {
				algorithm = "fixed-window"
			}

			// Generate rate limit key based on algorithm
			var key string
			if algorithm == "sliding-window" {
				// Sliding window uses a base key without time component
				key = ratelimit.GenerateBaseKey(ip, r.URL.Path)
			} else {
				// Fixed window uses a key with time window slot
				key = ratelimit.GenerateKeyWithWindow(ip, r.URL.Path, window)
			}

			// Check rate limit using the configured algorithm
			remaining, allowed, err := limiter.CheckWithAlgorithm(r.Context(), key, window, max, algorithm)
			if err != nil {
				slog.Error("rate limit check failed",
					"error", err,
					"ip", ip,
					"path", r.URL.Path,
				)
				// Continue on error to avoid blocking legitimate traffic
				next.ServeHTTP(w, r)
				return
			}

			// Add rate limit headers
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", max))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", window))

			// Block if rate limit exceeded
			if !allowed {
				slog.Warn("rate limit exceeded",
					"ip", ip,
					"path", r.URL.Path,
				)
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request, config *domain.Config) string {
	// Check configured IP address headers
	if config.Advanced != nil && config.Advanced.IPAddress != nil {
		for _, header := range config.Advanced.IPAddress.IPAddressHeaders {
			if ip := r.Header.Get(header); ip != "" {
				// Handle comma-separated list (e.g., X-Forwarded-For)
				ips := strings.Split(ip, ",")
				if len(ips) > 0 {
					return strings.TrimSpace(ips[0])
				}
			}
		}
	}

	// Fallback to standard headers
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		ips := strings.Split(ip, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// getRateLimitConfig returns the rate limit configuration for a given path
func getRateLimitConfig(path string, config *domain.RateLimitOptions) (window int, max int) {
	// Check custom rules first
	if config.CustomRules != nil {
		for rulePath, rule := range config.CustomRules {
			if matchPath(path, rulePath) {
				return rule.Window, rule.Max
			}
		}
	}

	// Use default configuration
	return config.Window, config.Max
}

// matchPath checks if a path matches a pattern
// Supports exact match and wildcard patterns
func matchPath(path string, pattern string) bool {
	// Exact match
	if path == pattern {
		return true
	}

	// Wildcard pattern matching
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}

	return false
}
