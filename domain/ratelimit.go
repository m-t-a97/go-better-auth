package domain

import "time"

// RateLimitError represents a rate limit error
type RateLimitError struct {
	Code       string
	Message    string
	Status     int
	RetryAfter int // Seconds until retry is allowed
}

func (e *RateLimitError) Error() string {
	return e.Message
}

// Common rate limit errors
var (
	ErrRateLimitExceeded = &RateLimitError{
		Code:       "rate_limit_exceeded",
		Message:    "Too many requests. Please try again later",
		Status:     429,
		RetryAfter: 60,
	}
)

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	// Limit is the maximum number of requests allowed
	Limit int64

	// Window is the time window for the limit
	Window time.Duration

	// KeyGenerator generates a key for identifying the requester
	// Common patterns: IP address, user ID, API key
	KeyGenerator func() string
}

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	// Allow checks if a request should be allowed and returns whether it's allowed
	// retryAfter is in seconds
	Allow(key string, limit int64, window time.Duration) (allowed bool, retryAfter int, err error)

	// Reset resets the rate limit for a key
	Reset(key string) error

	// GetRemaining returns the number of remaining requests for a key
	GetRemaining(key string, limit int64, window time.Duration) (remaining int64, err error)

	// Close closes the rate limiter (for cleanup)
	Close() error
}

// RateLimitStrategy defines how to generate keys for rate limiting
type RateLimitStrategy string

const (
	// StrategyIP uses the client IP address
	StrategyIP RateLimitStrategy = "ip"

	// StrategyUserID uses the authenticated user ID
	StrategyUserID RateLimitStrategy = "user_id"

	// StrategyAPIKey uses the API key
	StrategyAPIKey RateLimitStrategy = "api_key"

	// StrategyIPAndEndpoint combines IP and endpoint path
	StrategyIPAndEndpoint RateLimitStrategy = "ip_endpoint"
)
