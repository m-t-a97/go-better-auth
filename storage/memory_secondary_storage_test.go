package storage

import (
	"context"
	"testing"
	"time"
)

func TestMemorySecondaryStorage_SetAndGet(t *testing.T) {
	storage := NewMemorySecondaryStorage()
	ctx := context.Background()

	key := "test-key"
	value := "test-value"

	// Set without TTL
	err := storage.Set(ctx, key, value, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Get
	got, err := storage.Get(ctx, key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if got != value {
		t.Errorf("expected %s, got %v", value, got)
	}
}

func TestMemorySecondaryStorage_SetWithTTL(t *testing.T) {
	storage := NewMemorySecondaryStorage()
	ctx := context.Background()

	key := "test-key"
	value := "test-value"

	// Set with 1 second TTL
	err := storage.Set(ctx, key, value, 1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Get immediately
	got, err := storage.Get(ctx, key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != value {
		t.Errorf("expected %s, got %v", value, got)
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	// Get after expiration
	_, err = storage.Get(ctx, key)
	if err == nil {
		t.Error("expected error for expired key, got nil")
	}
}

func TestMemorySecondaryStorage_Delete(t *testing.T) {
	storage := NewMemorySecondaryStorage()
	ctx := context.Background()

	key := "test-key"
	value := "test-value"

	// Set
	err := storage.Set(ctx, key, value, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Delete
	err = storage.Delete(ctx, key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Get after delete
	_, err = storage.Get(ctx, key)
	if err == nil {
		t.Error("expected error for deleted key, got nil")
	}
}

func TestMemorySecondaryStorage_CleanExpired(t *testing.T) {
	storage := NewMemorySecondaryStorage()
	ctx := context.Background()

	// Set items with different TTLs
	storage.Set(ctx, "key1", "value1", 1)  // Expires in 1 second
	storage.Set(ctx, "key2", "value2", 10) // Expires in 10 seconds
	storage.Set(ctx, "key3", "value3", 0)  // Never expires

	// Initial count
	if storage.Count() != 3 {
		t.Errorf("expected count 3, got %d", storage.Count())
	}

	// Wait for first item to expire
	time.Sleep(1100 * time.Millisecond)

	// Clean expired
	cleaned := storage.CleanExpired()
	if cleaned != 1 {
		t.Errorf("expected 1 cleaned item, got %d", cleaned)
	}

	// Count should be 2
	if storage.Count() != 2 {
		t.Errorf("expected count 2, got %d", storage.Count())
	}
}

func TestMemorySecondaryStorage_Clear(t *testing.T) {
	storage := NewMemorySecondaryStorage()
	ctx := context.Background()

	// Set multiple items
	storage.Set(ctx, "key1", "value1", 0)
	storage.Set(ctx, "key2", "value2", 0)
	storage.Set(ctx, "key3", "value3", 0)

	// Clear
	storage.Clear()

	// Count should be 0
	if storage.Count() != 0 {
		t.Errorf("expected count 0, got %d", storage.Count())
	}
}

func TestMemorySecondaryStorage_Overwrite(t *testing.T) {
	storage := NewMemorySecondaryStorage()
	ctx := context.Background()

	key := "test-key"
	value1 := "value1"
	value2 := "value2"

	// Set first value
	err := storage.Set(ctx, key, value1, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Set second value (overwrite)
	err = storage.Set(ctx, key, value2, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Get should return second value
	got, err := storage.Get(ctx, key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != value2 {
		t.Errorf("expected %s, got %v", value2, got)
	}
}
