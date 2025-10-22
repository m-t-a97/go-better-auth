package storage

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// memoryItem represents an item stored in memory with optional expiration
type memoryItem struct {
	value     string
	expiresAt *time.Time
}

// InMemorySecondaryStorage implements SecondaryStorage interface using in-memory storage
// This is useful for testing and development without external dependencies
type InMemorySecondaryStorage struct {
	mu    sync.RWMutex
	items map[string]*memoryItem
}

// NewInMemorySecondaryStorage creates a new in-memory secondary storage instance
func NewInMemorySecondaryStorage() *InMemorySecondaryStorage {
	return &InMemorySecondaryStorage{
		items: make(map[string]*memoryItem),
	}
}

// Get retrieves the value for the given key from memory
func (s *InMemorySecondaryStorage) Get(ctx context.Context, key string) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, exists := s.items[key]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	// Check if expired
	if item.expiresAt != nil && item.expiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("key has expired: %s", key)
	}

	return item.value, nil
}

// Set stores the value for the given key in memory with optional TTL
// ttlSeconds is the time to live in seconds. If 0 or negative, the key won't expire.
func (s *InMemorySecondaryStorage) Set(ctx context.Context, key string, value string, ttlSeconds int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item := &memoryItem{
		value: value,
	}

	if ttlSeconds > 0 {
		expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
		item.expiresAt = &expiresAt
	}

	s.items[key] = item
	return nil
}

// Delete removes the value for the given key from memory
func (s *InMemorySecondaryStorage) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.items, key)
	return nil
}

// CleanExpired removes all expired items from memory
// This should be called periodically by a background job
func (s *InMemorySecondaryStorage) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	now := time.Now()

	for key, item := range s.items {
		if item.expiresAt != nil && item.expiresAt.Before(now) {
			delete(s.items, key)
			count++
		}
	}

	return count
}

// GetAllKeys returns all keys in the storage (for testing purposes)
func (s *InMemorySecondaryStorage) GetAllKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.items))
	for key := range s.items {
		keys = append(keys, key)
	}
	return keys
}

// Count returns the number of items in the storage (for testing purposes)
func (s *InMemorySecondaryStorage) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.items)
}

// Clear removes all items from memory (for testing purposes)
func (s *InMemorySecondaryStorage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items = make(map[string]*memoryItem)
}
