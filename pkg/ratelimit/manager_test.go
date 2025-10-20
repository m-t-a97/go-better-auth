package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryRateLimiterAllow tests the Allow method
func TestMemoryRateLimiterAllow(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")

	tests := []struct {
		name      string
		key       string
		limit     int64
		window    time.Duration
		requests  int
		wantAllow bool
		wantRetry int
	}{
		{
			name:      "Allow first request",
			key:       "user:1",
			limit:     5,
			window:    time.Minute,
			requests:  1,
			wantAllow: true,
			wantRetry: 0,
		},
		{
			name:      "Allow up to limit",
			key:       "user:2",
			limit:     3,
			window:    time.Minute,
			requests:  3,
			wantAllow: true,
			wantRetry: 0,
		},
		{
			name:      "Reject over limit",
			key:       "user:3",
			limit:     2,
			window:    time.Minute,
			requests:  3,
			wantAllow: false,
			wantRetry: 1, // At least 1 second wait
		},
		{
			name:      "Reject zero limit",
			key:       "user:4",
			limit:     0,
			window:    time.Minute,
			requests:  1,
			wantAllow: true, // 0 limit means no limit
			wantRetry: 0,
		},
		{
			name:      "Reject zero window",
			key:       "user:5",
			limit:     5,
			window:    0,
			requests:  1,
			wantAllow: true, // 0 window means no limit
			wantRetry: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lastAllow bool
			var lastRetry int

			for i := 0; i < tt.requests; i++ {
				allow, retry, err := limiter.Allow(tt.key, tt.limit, tt.window)
				require.NoError(t, err)
				lastAllow = allow
				lastRetry = retry

				// Fail fast on unexpected rejection
				if i < int(tt.limit) && !allow {
					t.Fatalf("Unexpected rejection at request %d", i+1)
				}
			}

			assert.Equal(t, tt.wantAllow, lastAllow)
			if !lastAllow {
				if lastRetry <= tt.wantRetry-1 {
					t.Errorf("Expected retry after to be > %d, got %d", tt.wantRetry-1, lastRetry)
				}
			}
		})
	}
}

// TestMemoryRateLimiterGetRemaining tests the GetRemaining method
func TestMemoryRateLimiterGetRemaining(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	key := "user:1"
	limit := int64(5)
	window := time.Minute

	// Make 3 requests
	for i := 0; i < 3; i++ {
		_, _, err := limiter.Allow(key, limit, window)
		require.NoError(t, err)
	}

	remaining, err := limiter.GetRemaining(key, limit, window)
	require.NoError(t, err)
	assert.Equal(t, int64(2), remaining)

	// Make 2 more requests
	for i := 0; i < 2; i++ {
		_, _, err := limiter.Allow(key, limit, window)
		require.NoError(t, err)
	}

	remaining, err = limiter.GetRemaining(key, limit, window)
	require.NoError(t, err)
	assert.Equal(t, int64(0), remaining)
}

// TestMemoryRateLimiterReset tests the Reset method
func TestMemoryRateLimiterReset(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	key := "user:1"
	limit := int64(2)
	window := time.Minute

	// Fill the bucket
	limiter.Allow(key, limit, window)
	limiter.Allow(key, limit, window)

	// Should be rejected now
	allow, _, err := limiter.Allow(key, limit, window)
	require.NoError(t, err)
	assert.False(t, allow)

	// Reset
	err = limiter.Reset(key)
	require.NoError(t, err)

	// Should be allowed again
	allow, _, err = limiter.Allow(key, limit, window)
	require.NoError(t, err)
	assert.True(t, allow)
}

// TestMemoryRateLimiterWindowExpiry tests that requests expire after window
func TestMemoryRateLimiterWindowExpiry(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	key := "user:1"
	limit := int64(2)
	window := 100 * time.Millisecond

	// Fill the bucket
	limiter.Allow(key, limit, window)
	limiter.Allow(key, limit, window)

	// Should be rejected
	allow, _, err := limiter.Allow(key, limit, window)
	require.NoError(t, err)
	assert.False(t, allow)

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	allow, _, err = limiter.Allow(key, limit, window)
	require.NoError(t, err)
	assert.True(t, allow)
}

// TestMemoryRateLimiterMultipleKeys tests that different keys are independent
func TestMemoryRateLimiterMultipleKeys(t *testing.T) {
	limiter := NewMemoryRateLimiter("test:")
	limit := int64(2)
	window := time.Minute

	// Fill bucket for user:1
	limiter.Allow("user:1", limit, window)
	limiter.Allow("user:1", limit, window)

	// user:1 should be rejected
	allow1, _, _ := limiter.Allow("user:1", limit, window)
	assert.False(t, allow1)

	// user:2 should be allowed
	allow2, _, _ := limiter.Allow("user:2", limit, window)
	assert.True(t, allow2)
}

// TestDefaultPresets tests that default presets have reasonable values
func TestDefaultPresets(t *testing.T) {
	presets := DefaultPresets()

	if presets.Auth <= 0 {
		t.Errorf("Expected Auth > 0, got %d", presets.Auth)
	}
	if presets.MFA <= 0 {
		t.Errorf("Expected MFA > 0, got %d", presets.MFA)
	}
	if presets.General <= 0 {
		t.Errorf("Expected General > 0, got %d", presets.General)
	}
	if presets.Sensitive <= 0 {
		t.Errorf("Expected Sensitive > 0, got %d", presets.Sensitive)
	}

	// MFA should be stricter than auth
	if presets.MFA >= presets.Auth {
		t.Errorf("Expected MFA < Auth, got MFA=%d, Auth=%d", presets.MFA, presets.Auth)
	}

	// General should be most permissive
	if presets.General <= presets.Auth {
		t.Errorf("Expected General > Auth, got General=%d, Auth=%d", presets.General, presets.Auth)
	}
}

// BenchmarkMemoryRateLimiterAllow benchmarks the Allow method
func BenchmarkMemoryRateLimiterAllow(b *testing.B) {
	limiter := NewMemoryRateLimiter("bench:")
	limit := int64(1000)
	window := time.Hour

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow("user:1", limit, window)
	}
}

// BenchmarkMemoryRateLimiterGetRemaining benchmarks the GetRemaining method
func BenchmarkMemoryRateLimiterGetRemaining(b *testing.B) {
	limiter := NewMemoryRateLimiter("bench:")
	limit := int64(1000)
	window := time.Hour

	limiter.Allow("user:1", limit, window)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.GetRemaining("user:1", limit, window)
	}
}
