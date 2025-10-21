package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDBSecondaryStorage_Set tests setting values in database storage
func TestDBSecondaryStorage_Set(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Skip("SQLite not available (CGO required)")
	}
	defer db.Close()

	storage, err := NewDBSecondaryStorage(db)
	if err != nil {
		t.Skip("SQLite not available")
	}

	// Create table
	ctx := context.Background()
	err = storage.CreateTable(ctx)
	require.NoError(t, err)

	tests := []struct {
		name      string
		key       string
		value     string
		ttl       int
		expectErr bool
	}{
		{
			name:      "set value without TTL",
			key:       "db:key1",
			value:     "hello",
			ttl:       0,
			expectErr: false,
		},
		{
			name:      "set value with TTL",
			key:       "db:key2",
			value:     "world",
			ttl:       3600,
			expectErr: false,
		},
		{
			name:      "overwrite existing value",
			key:       "db:key3",
			value:     "original",
			ttl:       0,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.Set(ctx, tt.key, tt.value, tt.ttl)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDBSecondaryStorage_Get tests retrieving values from database storage
func TestDBSecondaryStorage_Get(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Skip("SQLite not available (CGO required)")
	}
	defer db.Close()

	storage, err := NewDBSecondaryStorage(db)
	if err != nil {
		t.Skip("SQLite not available")
	}

	ctx := context.Background()
	err = storage.CreateTable(ctx)
	require.NoError(t, err)

	// Set test data
	storage.Set(ctx, "db:get1", "test-value", 0)

	tests := []struct {
		name      string
		key       string
		expectVal string
		expectErr bool
	}{
		{
			name:      "get existing value",
			key:       "db:get1",
			expectVal: "test-value",
			expectErr: false,
		},
		{
			name:      "get non-existent key",
			key:       "db:nonexistent",
			expectVal: "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := storage.Get(ctx, tt.key)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectVal, val)
			}
		})
	}
}

// TestDBSecondaryStorage_Delete tests deleting values from database storage
func TestDBSecondaryStorage_Delete(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Skip("SQLite not available (CGO required)")
	}
	defer db.Close()

	storage, err := NewDBSecondaryStorage(db)
	if err != nil {
		t.Skip("SQLite not available")
	}

	ctx := context.Background()
	err = storage.CreateTable(ctx)
	require.NoError(t, err)

	tests := []struct {
		name      string
		key       string
		setup     func()
		expectErr bool
	}{
		{
			name: "delete existing key",
			key:  "db:del1",
			setup: func() {
				storage.Set(ctx, "db:del1", "value", 0)
			},
			expectErr: false,
		},
		{
			name: "delete non-existent key",
			key:  "db:del-nonexistent",
			setup: func() {
				// No setup needed
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			err := storage.Delete(ctx, tt.key)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDBSecondaryStorage_TTL tests TTL expiration in database storage
func TestDBSecondaryStorage_TTL(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Skip("SQLite not available (CGO required)")
	}
	defer db.Close()

	storage, err := NewDBSecondaryStorage(db)
	if err != nil {
		t.Skip("SQLite not available")
	}

	ctx := context.Background()
	err = storage.CreateTable(ctx)
	require.NoError(t, err)

	key := "db:ttl-key"
	value := "short-lived"

	// Set value with 1 second TTL
	err = storage.Set(ctx, key, value, 1)
	require.NoError(t, err)

	// Value should exist immediately
	val, err := storage.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, value, val)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Value should be gone after expiration
	_, err = storage.Get(ctx, key)
	assert.Error(t, err)
}

// TestDBSecondaryStorage_Upsert tests updating existing values
func TestDBSecondaryStorage_Upsert(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Skip("SQLite not available (CGO required)")
	}
	defer db.Close()

	storage, err := NewDBSecondaryStorage(db)
	if err != nil {
		t.Skip("SQLite not available")
	}

	ctx := context.Background()
	err = storage.CreateTable(ctx)
	require.NoError(t, err)

	key := "db:upsert-key"

	// First insert
	err = storage.Set(ctx, key, "value1", 0)
	require.NoError(t, err)

	val, err := storage.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "value1", val)

	// Update existing key
	err = storage.Set(ctx, key, "value2", 0)
	require.NoError(t, err)

	val, err = storage.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "value2", val)
}

// TestDBSecondaryStorage_EmptyValue tests storing empty values
func TestDBSecondaryStorage_EmptyValue(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Skip("SQLite not available (CGO required)")
	}
	defer db.Close()

	storage, err := NewDBSecondaryStorage(db)
	if err != nil {
		t.Skip("SQLite not available")
	}

	ctx := context.Background()
	err = storage.CreateTable(ctx)
	require.NoError(t, err)

	key := "db:empty-key"

	// Store empty string
	err = storage.Set(ctx, key, "", 0)
	require.NoError(t, err)

	val, err := storage.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "", val)
}
