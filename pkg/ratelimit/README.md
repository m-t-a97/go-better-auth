# Rate Limiting 🚦

A production-ready rate limiting package for Go Better Auth, using Redis as the backend with support for in-memory fallback.

## Features

- **Token Bucket Algorithm**: Fair and efficient rate limiting using the token bucket pattern
- **Redis Backend**: Distributed rate limiting for multi-instance deployments
- **In-Memory Fallback**: Optional in-memory rate limiter for development and testing
- **Multiple Strategies**: IP-based, User ID-based, API Key-based, and combined strategies
- **Configurable Limits**: Per-endpoint rate limiting with preset configurations
- **Detailed Headers**: Standard HTTP rate limit headers included in all responses
- **Easy Integration**: Simple middleware integration with Chi and other HTTP routers

## Installation

```bash
go get github.com/redis/go-redis/v9
```

## Usage

### Basic Setup with Redis

```go
package main

import (
	"github.com/redis/go-redis/v9"
	"github.com/m-t-a97/go-better-auth/pkg/ratelimit"
	"github.com/m-t-a97/go-better-auth/internal/domain"
	"time"
)

func main() {
	// Create Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Create rate limiter
	limiter := ratelimit.NewRedisRateLimiter(redisClient, "auth:")

	// Create middleware with IP-based rate limiting
	// 100 requests per hour
	middleware := ratelimit.NewMiddleware(
		limiter,
		domain.StrategyIP,
		100,
		time.Hour,
	)

	// Apply to router
	r.Use(middleware.Handler)
}
```

### In-Memory Fallback for Development

```go
// Use in-memory rate limiter for development/testing
limiter := ratelimit.NewMemoryRateLimiter("auth:")

middleware := ratelimit.NewMiddleware(
	limiter,
	domain.StrategyIP,
	100,
	time.Hour,
)
```

### Per-Endpoint Rate Limiting

```go
// Different limits for different endpoints
presets := ratelimit.DefaultPresets()

// Create middleware with endpoint-specific limits
authMiddleware := ratelimit.NewMiddleware(
	limiter,
	domain.StrategyIP,
	presets.Auth,
	15*time.Minute,
)

mfaMiddleware := ratelimit.NewMiddleware(
	limiter,
	domain.StrategyIP,
	presets.MFA,
	5*time.Minute,
)

sensitiveMiddleware := ratelimit.NewMiddleware(
	limiter,
	domain.StrategyIP,
	presets.Sensitive,
	30*time.Minute,
)

// Apply to specific routes
r.Route("/api/auth", func(r chi.Router) {
	// Auth endpoints: 5 attempts per 15 minutes
	r.Use(authMiddleware.Handler)
	r.Post("/sign-up/email", handler.SignUpEmail)
	r.Post("/sign-in/email", handler.SignInEmail)
	
	// MFA endpoints: 3 attempts per 5 minutes
	r.Route("/mfa", func(r chi.Router) {
		r.Use(mfaMiddleware.Handler)
		r.Post("/verify", mfaHandler.VerifyMFACode)
	})
	
	// Sensitive operations: 3 attempts per 30 minutes
	r.Post("/change-password", sensitiveMiddleware.Handler(handler.ChangePassword))
})
```

### Rate Limiting Strategies

#### 1. IP-Based (Default)

Rate limit by client IP address. Best for public APIs.

```go
middleware := ratelimit.NewMiddleware(
	limiter,
	domain.StrategyIP,
	100,
	time.Hour,
)
```

#### 2. User ID-Based

Rate limit by authenticated user. Best for authenticated endpoints.

```go
middleware := ratelimit.NewMiddleware(
	limiter,
	domain.StrategyUserID,
	1000,
	time.Hour,
)
```

#### 3. API Key-Based

Rate limit by API key from Authorization header.

```go
middleware := ratelimit.NewMiddleware(
	limiter,
	domain.StrategyAPIKey,
	5000,
	time.Hour,
)
```

#### 4. IP + Endpoint

Rate limit by IP and endpoint combination.

```go
middleware := ratelimit.NewMiddleware(
	limiter,
	domain.StrategyIPAndEndpoint,
	100,
	time.Hour,
)
```

## Default Presets

The package provides sensible defaults for common use cases:

```go
presets := ratelimit.DefaultPresets()

// Auth endpoints: 5 attempts per 15 minutes
// MFA verification: 3 attempts per 5 minutes  
// General API: 100 requests per hour
// Sensitive operations: 3 attempts per 30 minutes
```

## HTTP Headers

The middleware adds the following standard rate limit headers to all responses:

- `X-RateLimit-Limit`: Maximum requests allowed in the window
- `X-RateLimit-Remaining`: Requests remaining in the current window
- `X-RateLimit-Reset`: Unix timestamp when the limit resets
- `Retry-After`: (When rate limited) Seconds to wait before retrying

## Rate Limit Response

When a client exceeds the rate limit, they receive a `429 Too Many Requests` response:

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Too many requests. Please try again later"
  },
  "retryAfter": 60
}
```

## Architecture

### Token Bucket Algorithm

The rate limiter uses the token bucket algorithm:

1. Each key starts with a full bucket of tokens
2. Each request consumes one token
3. Tokens are refilled over time according to the window
4. When the bucket is empty, requests are rejected

This algorithm is:
- **Fair**: All clients get equal treatment
- **Efficient**: O(log n) complexity with Redis sorted sets
- **Flexible**: Handles burst traffic gracefully
- **Accurate**: Precise token tracking per second

### Redis Implementation

Uses Redis sorted sets for efficient O(log n) operations:

- **Score**: Request timestamp (milliseconds)
- **Member**: Request identifier (timestamp + random)
- **Window**: Sliding window of requests

Lua script ensures atomic operations and prevents race conditions.

### In-Memory Implementation

For development/testing, uses a simple in-memory map:

- Not suitable for distributed systems
- No persistence
- Manual cleanup via Close()

## Integration with Go Better Auth

### Example: Adding Rate Limiting to Auth Handler

```go
import (
	"github.com/redis/go-redis/v9"
	"github.com/m-t-a97/go-better-auth/pkg/ratelimit"
	"github.com/m-t-a97/go-better-auth/internal/domain"
	"time"
)

// Initialize Redis
redisClient := redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

// Create rate limiter
limiter := ratelimit.NewRedisRateLimiter(redisClient, "auth:")

// Get presets
presets := ratelimit.DefaultPresets()

// Create middlewares for different endpoint types
authLimiter := ratelimit.NewMiddleware(limiter, domain.StrategyIP, presets.Auth, 15*time.Minute)
mfaLimiter := ratelimit.NewMiddleware(limiter, domain.StrategyIP, presets.MFA, 5*time.Minute)

// Apply in SetupRouter()
r.Route("/api/auth", func(r chi.Router) {
	// Rate limit auth endpoints
	r.Post("/sign-up/email", authLimiter.Handler(h.SignUpEmail))
	r.Post("/sign-in/email", authLimiter.Handler(h.SignInEmail))
	
	// Rate limit MFA verification
	r.Route("/mfa", func(r chi.Router) {
		r.Post("/verify", mfaLimiter.Handler(mfaHandler.VerifyMFACode))
	})
})
```

## Performance Considerations

- **Redis Connection Pool**: Reuse the same Redis client across handlers
- **Sliding Window**: Each request is O(log n) with Redis
- **Cleanup**: Old entries are automatically expired in Redis
- **Memory**: O(1) per active key in Redis

## Error Handling

The middleware gracefully handles Redis errors:

```go
// If Redis is unavailable, requests are allowed through
// (fail-open design)
if err != nil {
	next.ServeHTTP(w, r)
	return
}
```

Configure your monitoring to alert on Redis errors.

## Testing

```go
func TestRateLimit(t *testing.T) {
	// Use in-memory limiter for tests
	limiter := ratelimit.NewMemoryRateLimiter("test:")
	
	// Test allowing requests
	for i := 0; i < 5; i++ {
		allowed, _, _ := limiter.Allow("user:1", 5, time.Minute)
		assert.True(t, allowed)
	}
	
	// Test rejecting on limit
	allowed, retryAfter, _ := limiter.Allow("user:1", 5, time.Minute)
	assert.False(t, allowed)
	assert.Greater(t, retryAfter, 0)
	
	// Test reset
	limiter.Reset("user:1")
	allowed, _, _ := limiter.Allow("user:1", 5, time.Minute)
	assert.True(t, allowed)
}
```

## Best Practices

1. **Use Redis in Production**: Always use `RedisRateLimiter` in production for distributed systems
2. **Strategy by Endpoint**: Choose rate limiting strategy based on endpoint security needs
3. **Conservative Defaults**: Start with stricter limits and relax based on metrics
4. **Monitor**: Track rate limit hits and adjust limits as needed
5. **Document**: Include rate limits in your API documentation
6. **Graceful Degradation**: Use fail-open design if Redis becomes unavailable

## Related Documentation

- [CSRF Protection](../csrf/README.md)
- [MFA Setup](../mfa/README.md)
- [Framework Integration](../../docs/FRAMEWORK_INTEGRATION.md)
