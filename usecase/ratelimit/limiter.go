package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/GoBetterAuth/go-better-auth/storage"
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
	return l.CheckWithAlgorithm(ctx, key, window, max, "fixed-window")
}

// CheckWithAlgorithm checks if a request should be allowed based on rate limits using the specified algorithm
// Returns remaining requests and whether the request should be allowed
func (l *Limiter) CheckWithAlgorithm(ctx context.Context, key string, window int, max int, algorithm string) (remaining int, allowed bool, err error) {
	if window <= 0 || max <= 0 {
		return 0, false, fmt.Errorf("invalid rate limit configuration: window=%d, max=%d", window, max)
	}

	switch algorithm {
	case "sliding-window":
		return l.checkSlidingWindow(ctx, key, window, max)
	case "fixed-window", "":
		return l.checkFixedWindow(ctx, key, window, max)
	default:
		return 0, false, fmt.Errorf("unknown rate limit algorithm: %s", algorithm)
	}
}

// checkFixedWindow implements the fixed window counter algorithm
func (l *Limiter) checkFixedWindow(ctx context.Context, key string, window int, max int) (remaining int, allowed bool, err error) {
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

// checkSlidingWindow implements the sliding window counter algorithm
// This algorithm uses a weighted count from both the current and previous window
// to provide smoother rate limiting at window boundaries
func (l *Limiter) checkSlidingWindow(ctx context.Context, key string, window int, max int) (remaining int, allowed bool, err error) {
	now := time.Now().Unix()
	currentWindowSlot := now / int64(window)
	previousWindowSlot := currentWindowSlot - 1

	// Calculate the percentage of the current window that has elapsed
	elapsedInCurrentWindow := now % int64(window)
	percentageInCurrentWindow := float64(elapsedInCurrentWindow) / float64(window)
	percentageInPreviousWindow := 1.0 - percentageInCurrentWindow

	// Get counts for current and previous windows
	currentKey := l.rateLimitKey(fmt.Sprintf("%s:%d", key, currentWindowSlot))
	previousKey := l.rateLimitKey(fmt.Sprintf("%s:%d", key, previousWindowSlot))

	currentCount := l.getCount(ctx, currentKey)
	previousCount := l.getCount(ctx, previousKey)

	// Calculate weighted count using sliding window algorithm
	// Weight the previous window count by how much of it overlaps with our current time window
	weightedCount := float64(previousCount)*percentageInPreviousWindow + float64(currentCount)

	l.logger.Debug("sliding window rate limit check",
		"key", key,
		"currentCount", currentCount,
		"previousCount", previousCount,
		"weightedCount", weightedCount,
		"percentageInCurrentWindow", percentageInCurrentWindow,
		"max", max,
	)

	// Check if limit exceeded using weighted count
	if int(weightedCount) >= max {
		l.logger.Debug("rate limit exceeded (sliding window)",
			"key", key,
			"weightedCount", weightedCount,
			"max", max,
		)
		return 0, false, nil
	}

	// Increment counter in current window
	currentCount++
	if err := l.secondary.Set(ctx, currentKey, strconv.Itoa(currentCount), window*2); err != nil {
		l.logger.Error("failed to update rate limit counter",
			"key", key,
			"error", err,
		)
		// Allow request on error to avoid blocking legitimate traffic
		return max - int(weightedCount), true, fmt.Errorf("failed to update rate limit counter: %w", err)
	}

	// Recalculate weighted count after increment
	weightedCount = float64(previousCount)*percentageInPreviousWindow + float64(currentCount)
	remaining = max - int(weightedCount)
	if remaining < 0 {
		remaining = 0
	}

	l.logger.Debug("rate limit check passed (sliding window)",
		"key", key,
		"currentCount", currentCount,
		"weightedCount", weightedCount,
		"max", max,
		"remaining", remaining,
	)

	return remaining, true, nil
}

// getCount is a helper method to get count from storage, returning 0 if not found
func (l *Limiter) getCount(ctx context.Context, cacheKey string) int {
	cached, err := l.secondary.Get(ctx, cacheKey)
	if err != nil || cached == nil {
		return 0
	}

	if cachedStr, ok := cached.(string); ok {
		if count, parseErr := strconv.Atoi(cachedStr); parseErr == nil {
			return count
		}
	}

	return 0
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
// This ensures the key is unique per time window (for fixed window algorithm)
func GenerateKeyWithWindow(ip string, path string, window int) string {
	// Calculate the current window slot
	now := time.Now().Unix()
	windowSlot := now / int64(window)
	return fmt.Sprintf("%s:%s:%d", ip, path, windowSlot)
}

// GenerateBaseKey creates a base rate limit key without time component
// This is used for sliding window algorithm which manages time slots internally
func GenerateBaseKey(ip string, path string) string {
	return fmt.Sprintf("%s:%s", ip, path)
}
