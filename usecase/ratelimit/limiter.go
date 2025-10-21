package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/m-t-a97/go-better-auth/storage"
)

// Limiter provides rate limiting functionality using secondary storage
type Limiter struct {
	secondary storage.SecondaryStorage
	logger    *slog.Logger
}

// NewLimiter creates a new rate limiter
func NewLimiter(secondary storage.SecondaryStorage) *Limiter {
	return &Limiter{
		secondary: secondary,
		logger:    slog.Default(),
	}
}

// Check checks if a request should be allowed based on rate limits
// Returns remaining requests and whether the request should be allowed
func (l *Limiter) Check(ctx context.Context, key string, window int, max int) (remaining int, allowed bool, err error) {
	if window <= 0 || max <= 0 {
		return 0, false, fmt.Errorf("invalid rate limit configuration: window=%d, max=%d", window, max)
	}

	cacheKey := l.rateLimitKey(key)

	// Get current count
	cached, err := l.secondary.Get(ctx, cacheKey)
	count := 0

	if err == nil && cached != nil {
		// Parse count from cached value
		if cachedStr, ok := cached.(string); ok {
			if parsedCount, parseErr := strconv.Atoi(cachedStr); parseErr == nil {
				count = parsedCount
			}
		}
	}

	// Check if limit exceeded
	if count >= max {
		l.logger.Debug("rate limit exceeded",
			"key", key,
			"count", count,
			"max", max,
		)
		return 0, false, nil
	}

	// Increment counter
	count++
	if err := l.secondary.Set(ctx, cacheKey, strconv.Itoa(count), window); err != nil {
		l.logger.Error("failed to update rate limit counter",
			"key", key,
			"error", err,
		)
		// Allow request on error to avoid blocking legitimate traffic
		return max - count, true, fmt.Errorf("failed to update rate limit counter: %w", err)
	}

	remaining = max - count
	if remaining < 0 {
		remaining = 0
	}

	l.logger.Debug("rate limit check passed",
		"key", key,
		"count", count,
		"max", max,
		"remaining", remaining,
	)

	return remaining, true, nil
}

// Reset resets the rate limit counter for a given key
func (l *Limiter) Reset(ctx context.Context, key string) error {
	cacheKey := l.rateLimitKey(key)
	if err := l.secondary.Delete(ctx, cacheKey); err != nil {
		return fmt.Errorf("failed to reset rate limit: %w", err)
	}
	return nil
}

// GetCount returns the current count for a given key
func (l *Limiter) GetCount(ctx context.Context, key string) (int, error) {
	cacheKey := l.rateLimitKey(key)
	cached, err := l.secondary.Get(ctx, cacheKey)
	if err != nil {
		return 0, nil // Not found means 0 requests
	}

	if cachedStr, ok := cached.(string); ok {
		count, err := strconv.Atoi(cachedStr)
		if err != nil {
			return 0, fmt.Errorf("failed to parse count: %w", err)
		}
		return count, nil
	}

	return 0, nil
}

// rateLimitKey generates the cache key for rate limiting
func (l *Limiter) rateLimitKey(key string) string {
	return fmt.Sprintf("ratelimit:%s", key)
}

// GenerateKey creates a rate limit key from IP address and path
func GenerateKey(ip string, path string) string {
	return fmt.Sprintf("%s:%s:%d", ip, path, time.Now().Unix())
}

// GenerateKeyWithWindow creates a rate limit key that includes the time window
// This ensures the key is unique per time window
func GenerateKeyWithWindow(ip string, path string, window int) string {
	// Calculate the current window slot
	now := time.Now().Unix()
	windowSlot := now / int64(window)
	return fmt.Sprintf("%s:%s:%d", ip, path, windowSlot)
}
