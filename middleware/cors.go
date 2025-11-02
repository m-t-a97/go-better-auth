package middleware

import (
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain"
)

// CORSMiddleware creates a CORS middleware that validates origins and sets appropriate headers.
// It supports the following features:
// - Static origin validation
// - Dynamic origin validation via callback
// - Wildcard pattern matching for origins
// - Preflight request (OPTIONS) handling
// - Configurable allowed methods and headers
type CORSMiddleware struct {
	trustedOrigins    *domain.TrustedOriginsConfig
	allowedMethods    []string
	allowedHeaders    []string
	exposedHeaders    []string
	allowCredentials  bool
	maxAge            int
	continueOnMissing bool
}

// NewCORSMiddleware creates a new CORS middleware with default settings.
// By default, it:
// - Allows GET, POST, PUT, DELETE, PATCH, OPTIONS methods
// - Allows common headers (Content-Type, Authorization, etc.)
// - Allows credentials (cookies, auth headers)
// - Sets max age to 3600 seconds (1 hour)
func NewCORSMiddleware(trustedOrigins *domain.TrustedOriginsConfig) *CORSMiddleware {
	return &CORSMiddleware{
		trustedOrigins:    trustedOrigins,
		allowedMethods:    []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		allowedHeaders:    []string{"Content-Type", "Authorization", "X-Requested-With", "Accept"},
		exposedHeaders:    []string{"Content-Type", "Authorization"},
		allowCredentials:  true,
		maxAge:            3600,
		continueOnMissing: false,
	}
}

// WithAllowedMethods sets the allowed HTTP methods.
func (c *CORSMiddleware) WithAllowedMethods(methods []string) *CORSMiddleware {
	c.allowedMethods = methods
	return c
}

// WithAllowedHeaders sets the allowed headers.
func (c *CORSMiddleware) WithAllowedHeaders(headers []string) *CORSMiddleware {
	c.allowedHeaders = headers
	return c
}

// WithExposedHeaders sets the exposed headers.
func (c *CORSMiddleware) WithExposedHeaders(headers []string) *CORSMiddleware {
	c.exposedHeaders = headers
	return c
}

// WithCredentials enables or disables credentials (cookies, auth headers).
func (c *CORSMiddleware) WithCredentials(allow bool) *CORSMiddleware {
	c.allowCredentials = allow
	return c
}

// WithMaxAge sets the max age for preflight requests in seconds.
func (c *CORSMiddleware) WithMaxAge(seconds int) *CORSMiddleware {
	c.maxAge = seconds
	return c
}

// WithContinueOnMissing sets whether to continue without CORS headers if origin is missing.
func (c *CORSMiddleware) WithContinueOnMissing(cont bool) *CORSMiddleware {
	c.continueOnMissing = cont
	return c
}

// Handler returns an http.HandlerFunc that wraps the given handler with CORS middleware.
func (c *CORSMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// If no origin header, decide based on continueOnMissing
		if origin == "" {
			if !c.continueOnMissing {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Check if origin is trusted
		if !c.trustedOrigins.IsOriginTrusted(origin, r) {
			// Origin is not trusted, continue without CORS headers
			if !c.continueOnMissing {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Origin is trusted, set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(c.allowedMethods, ", "))
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(c.allowedHeaders, ", "))
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(c.exposedHeaders, ", "))

		if c.allowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		w.Header().Set("Access-Control-Max-Age", intToString(c.maxAge))

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// intToString converts an int to a string.
func intToString(i int) string {
	if i < 0 {
		return "0"
	}
	// Simple conversion without strconv dependency
	if i == 0 {
		return "0"
	}
	result := ""
	for i > 0 {
		result = string(rune('0'+(i%10))) + result
		i /= 10
	}
	return result
}
