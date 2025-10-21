package storage

import (
	"context"
)

// SecondaryStorage provides secondary storage for session data and rate limiting.
type SecondaryStorage interface {
	// Get retrieves the value for the given key.
	Get(ctx context.Context, key string) (any, error)
	// Set sets the value for the given key with optional TTL (in seconds).
	Set(ctx context.Context, key string, value string, ttlSeconds int) error
	// Delete removes the value for the given key.
	Delete(ctx context.Context, key string) error
}
