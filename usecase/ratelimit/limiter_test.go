package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/storage"
)

func TestLimiter_Check_AllowsRequests(t *testing.T) {
	secondary := storage.NewMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 10 // 10 seconds
	max := 5     // 5 requests

	// First request should be allowed
	remaining, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed")
	}
	if remaining != 4 {
		t.Errorf("expected remaining 4, got %d", remaining)
	}

	// Make more requests up to the limit
	for i := 0; i < 4; i++ {
		remaining, allowed, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+2, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+2)
		}
		expectedRemaining := 3 - i
		if remaining != expectedRemaining {
			t.Errorf("expected remaining %d on request %d, got %d", expectedRemaining, i+2, remaining)
		}
	}
}

func TestLimiter_Check_BlocksExcessRequests(t *testing.T) {
	secondary := storage.NewMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 10 // 10 seconds
	max := 3     // 3 requests

	// Make requests up to the limit
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// Next request should be blocked
	remaining, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked")
	}
	if remaining != 0 {
		t.Errorf("expected remaining 0, got %d", remaining)
	}
}

func TestLimiter_Check_ResetAfterWindow(t *testing.T) {
	secondary := storage.NewMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 1 // 1 second
	max := 2    // 2 requests

	// Make requests up to the limit
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// Next request should be blocked
	_, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked before window expires")
	}

	// Wait for window to expire
	time.Sleep(1100 * time.Millisecond)

	// Request should be allowed after window expires
	remaining, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed after window expires")
	}
	if remaining != 1 {
		t.Errorf("expected remaining 1, got %d", remaining)
	}
}

func TestLimiter_Reset(t *testing.T) {
	secondary := storage.NewMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 10
	max := 2

	// Make requests up to the limit
	for i := 0; i < max; i++ {
		_, allowed, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// Next request should be blocked
	_, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Error("expected request to be blocked")
	}

	// Reset the counter
	if err := limiter.Reset(ctx, key); err != nil {
		t.Fatalf("failed to reset: %v", err)
	}

	// Request should be allowed after reset
	remaining, allowed, err := limiter.Check(ctx, key, window, max)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed after reset")
	}
	if remaining != 1 {
		t.Errorf("expected remaining 1, got %d", remaining)
	}
}

func TestLimiter_GetCount(t *testing.T) {
	secondary := storage.NewMemorySecondaryStorage()
	limiter := NewLimiter(secondary)
	ctx := context.Background()

	key := "test-key"
	window := 10
	max := 5

	// Initial count should be 0
	count, err := limiter.GetCount(ctx, key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}

	// Make 3 requests
	for i := 0; i < 3; i++ {
		_, _, err := limiter.Check(ctx, key, window, max)
		if err != nil {
			t.Fatalf("expected no error on request %d, got %v", i+1, err)
		}
	}

	// Count should be 3
	count, err = limiter.GetCount(ctx, key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
}

func TestGenerateKeyWithWindow(t *testing.T) {
	ip := "192.168.1.1"
	path := "/api/auth/signin"
	window := 10

	// Generate keys at different times in the same window
	key1 := GenerateKeyWithWindow(ip, path, window)
	time.Sleep(100 * time.Millisecond)
	key2 := GenerateKeyWithWindow(ip, path, window)

	// Should be the same key within the same window
	if key1 != key2 {
		t.Errorf("expected keys to be the same within window, got %s and %s", key1, key2)
	}

	// Generate key in different window (simulate by using a much larger window)
	// This is a simplistic test - in reality would need to wait for actual window to pass
	key3 := GenerateKeyWithWindow(ip, path, 1)
	time.Sleep(1100 * time.Millisecond)
	key4 := GenerateKeyWithWindow(ip, path, 1)

	// Should be different keys in different windows
	if key3 == key4 {
		t.Errorf("expected keys to be different in different windows, got %s and %s", key3, key4)
	}
}
