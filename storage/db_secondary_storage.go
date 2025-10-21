package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

// SecondaryStorageRow represents a row in the secondary storage table
type SecondaryStorageRow struct {
	Key       string
	Value     string
	ExpiresAt sql.NullTime
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DBSecondaryStorage implements SecondaryStorage interface using raw database connection.
// It provides key-value storage with optional TTL for session data and rate limiting.
// This is useful as a fallback when Redis is not available.
type DBSecondaryStorage struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewDBSecondaryStorage creates a new database-backed secondary storage instance.
// It uses a raw database connection for key-value storage operations.
func NewDBSecondaryStorage(db *sql.DB) (*DBSecondaryStorage, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}

	logger := slog.Default()

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	logger.Info("successfully initialized database secondary storage")

	return &DBSecondaryStorage{
		db:     db,
		logger: logger,
	}, nil
}

// Get retrieves the value for the given key from the database.
func (s *DBSecondaryStorage) Get(ctx context.Context, key string) (any, error) {
	s.logger.Debug("getting value from database", "key", key)

	var value string
	var expiresAt sql.NullTime

	query := `
		SELECT value, expires_at
		FROM secondary_storage
		WHERE key = $1
		LIMIT 1
	`

	err := s.db.QueryRowContext(ctx, query, key).Scan(&value, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get value from database: %w", err)
	}

	// Check if value has expired
	if expiresAt.Valid && expiresAt.Time.Before(time.Now()) {
		// Delete expired entry
		_ = s.Delete(ctx, key)
		return nil, fmt.Errorf("key has expired: %s", key)
	}

	return value, nil
}

// Set stores the value for the given key in the database with optional TTL.
// ttlSeconds is the time to live in seconds. If 0 or negative, the key won't expire.
func (s *DBSecondaryStorage) Set(ctx context.Context, key string, value string, ttlSeconds int) error {
	s.logger.Debug("setting value in database", "key", key, "ttl_seconds", ttlSeconds)

	var expiresAt *time.Time
	if ttlSeconds > 0 {
		expTime := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
		expiresAt = &expTime
	}

	// Try to insert, if key exists update it
	insertQuery := `
		INSERT INTO secondary_storage (key, value, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT (key) DO UPDATE SET
			value = $2,
			expires_at = $3,
			updated_at = NOW()
	`

	// For SQLite, use INSERT OR REPLACE
	updateQuery := `
		INSERT OR REPLACE INTO secondary_storage (key, value, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`

	// Try PostgreSQL syntax first, fall back to SQLite
	_, err := s.db.ExecContext(ctx, insertQuery, key, value, expiresAt)
	if err != nil {
		// Try SQLite syntax
		_, err = s.db.ExecContext(ctx, updateQuery, key, value, expiresAt)
		if err != nil {
			return fmt.Errorf("failed to set value in database: %w", err)
		}
	}

	return nil
}

// Delete removes the value for the given key from the database.
func (s *DBSecondaryStorage) Delete(ctx context.Context, key string) error {
	s.logger.Debug("deleting value from database", "key", key)

	query := `DELETE FROM secondary_storage WHERE key = $1`

	if _, err := s.db.ExecContext(ctx, query, key); err != nil {
		return fmt.Errorf("failed to delete value from database: %w", err)
	}

	return nil
}

// CreateTable creates the secondary_storage table if it doesn't exist.
// This should be called during application initialization.
func (s *DBSecondaryStorage) CreateTable(ctx context.Context) error {
	s.logger.Info("creating secondary_storage table")

	// Schema for both PostgreSQL and SQLite
	schema := `
		CREATE TABLE IF NOT EXISTS secondary_storage (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			expires_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`

	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("failed to create secondary_storage table: %w", err)
	}

	s.logger.Info("secondary_storage table created successfully")
	return nil
}
