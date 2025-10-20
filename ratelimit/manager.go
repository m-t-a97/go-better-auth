package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements the domain.RateLimiter interface using Redis
// Uses the token bucket algorithm for fair rate limiting
type RedisRateLimiter struct {
	client *redis.Client
	prefix string
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(client *redis.Client, prefix string) *RedisRateLimiter {
	if prefix == "" {
		prefix = "rate_limit:"
	}
	return &RedisRateLimiter{
		client: client,
		prefix: prefix,
	}
}

// Allow checks if a request should be allowed using the token bucket algorithm
func (r *RedisRateLimiter) Allow(key string, limit int64, window time.Duration) (bool, int, error) {
	if limit <= 0 || window <= 0 {
		return true, 0, nil // No limit configured
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fullKey := r.prefix + key
	now := time.Now()
	windowStart := now.Add(-window)

	// Lua script for atomic token bucket operation
	// Returns: [current_count, ttl_set]
	script := redis.NewScript(`
		local key = KEYS[1]
		local limit = tonumber(ARGV[1])
		local window = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])
		local window_start = tonumber(ARGV[4])

		-- Remove old entries outside the window
		redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

		-- Count requests in current window
		local current_count = redis.call('ZCARD', key)

		-- Check if limit exceeded
		if current_count >= limit then
			-- Get the oldest entry's score (timestamp of first request)
			local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
			if oldest[2] then
				local retry_after = math.ceil((oldest[2] + window - now) / 1000)
				return {0, retry_after}
			end
			return {0, math.ceil(window / 1000)}
		end

		-- Add current request with timestamp as both score and member
		redis.call('ZADD', key, now, now .. '_' .. math.random())

		-- Set expiry on the key
		redis.call('EXPIRE', key, math.ceil(window / 1000) + 1)

		return {1, 0}
	`)

	// Execute the script
	result, err := script.Run(
		ctx,
		r.client,
		[]string{fullKey},
		limit,
		window.Milliseconds(),
		now.UnixMilli(),
		windowStart.UnixMilli(),
	).Result()

	if err != nil {
		return false, 0, fmt.Errorf("rate limiter error: %w", err)
	}

	// Parse result
	vals := result.([]any)
	allowed := vals[0].(int64) == 1
	retryAfter := int(vals[1].(int64))

	return allowed, retryAfter, nil
}

// Reset resets the rate limit for a key
func (r *RedisRateLimiter) Reset(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fullKey := r.prefix + key
	return r.client.Del(ctx, fullKey).Err()
}

// GetRemaining returns the number of remaining requests for a key
func (r *RedisRateLimiter) GetRemaining(key string, limit int64, window time.Duration) (int64, error) {
	if limit <= 0 {
		return limit, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fullKey := r.prefix + key
	now := time.Now()
	windowStart := now.Add(-window)

	// Remove old entries outside the window
	_, err := r.client.ZRemRangeByScore(ctx, fullKey, "0", strconv.FormatInt(windowStart.UnixMilli(), 10)).Result()
	if err != nil {
		return 0, fmt.Errorf("error removing old entries: %w", err)
	}

	// Count current requests
	count, err := r.client.ZCard(ctx, fullKey).Result()
	if err != nil {
		return 0, fmt.Errorf("error getting request count: %w", err)
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// Close closes the rate limiter (closes the Redis connection if needed)
func (r *RedisRateLimiter) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// MemoryRateLimiter is an in-memory rate limiter for testing and development
// Note: Not suitable for distributed systems
type MemoryRateLimiter struct {
	buckets map[string][]time.Time
	prefix  string
}

// NewMemoryRateLimiter creates a new in-memory rate limiter
func NewMemoryRateLimiter(prefix string) *MemoryRateLimiter {
	if prefix == "" {
		prefix = "rate_limit:"
	}
	return &MemoryRateLimiter{
		buckets: make(map[string][]time.Time),
		prefix:  prefix,
	}
}

// Allow checks if a request should be allowed
func (m *MemoryRateLimiter) Allow(key string, limit int64, window time.Duration) (bool, int, error) {
	if limit <= 0 || window <= 0 {
		return true, 0, nil
	}

	fullKey := m.prefix + key
	now := time.Now()
	windowStart := now.Add(-window)

	// Get or create bucket for this key
	bucket, exists := m.buckets[fullKey]
	if !exists {
		bucket = []time.Time{}
	}

	// Remove entries outside the window
	filteredBucket := []time.Time{}
	for _, t := range bucket {
		if t.After(windowStart) {
			filteredBucket = append(filteredBucket, t)
		}
	}

	// Check limit
	if int64(len(filteredBucket)) >= limit {
		// Calculate retry after
		retryAfter := int(window.Seconds())
		if len(filteredBucket) > 0 {
			oldestTime := filteredBucket[0]
			retryAfter = int(window.Seconds()) - int(now.Sub(oldestTime).Seconds())
			if retryAfter < 0 {
				retryAfter = 0
			}
		}
		m.buckets[fullKey] = filteredBucket
		return false, retryAfter, nil
	}

	// Add current request
	filteredBucket = append(filteredBucket, now)
	m.buckets[fullKey] = filteredBucket

	return true, 0, nil
}

// Reset resets the rate limit for a key
func (m *MemoryRateLimiter) Reset(key string) error {
	fullKey := m.prefix + key
	delete(m.buckets, fullKey)
	return nil
}

// GetRemaining returns the number of remaining requests for a key
func (m *MemoryRateLimiter) GetRemaining(key string, limit int64, window time.Duration) (int64, error) {
	if limit <= 0 {
		return limit, nil
	}

	fullKey := m.prefix + key
	now := time.Now()
	windowStart := now.Add(-window)

	bucket, exists := m.buckets[fullKey]
	if !exists {
		return limit, nil
	}

	// Count entries within the window
	count := 0
	for _, t := range bucket {
		if t.After(windowStart) {
			count++
		}
	}

	remaining := limit - int64(count)
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// Close closes the rate limiter
func (m *MemoryRateLimiter) Close() error {
	m.buckets = make(map[string][]time.Time)
	return nil
}
