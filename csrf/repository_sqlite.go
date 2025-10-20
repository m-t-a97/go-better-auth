package csrf

import (
	"context"
	"database/sql"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// SQLiteRepository is a SQLite implementation of CSRFRepository
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new SQLite CSRF repository
func NewSQLiteRepository(db *sql.DB) *SQLiteRepository {
	return &SQLiteRepository{db: db}
}

// InitSchema initializes the CSRF tokens table
func (r *SQLiteRepository) InitSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS csrf_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token VARCHAR(255) UNIQUE NOT NULL,
			secret VARCHAR(255) NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE INDEX IF NOT EXISTS idx_csrf_expires_at ON csrf_tokens(expires_at);
		CREATE INDEX IF NOT EXISTS idx_csrf_token ON csrf_tokens(token);
	`

	_, err := r.db.ExecContext(ctx, schema)
	return err
}

// StoreToken stores a CSRF token and its secret
func (r *SQLiteRepository) StoreToken(token, secret string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT OR REPLACE INTO csrf_tokens (token, secret, expires_at)
		VALUES (?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query, token, secret, expiresAt)
	return err
}

// ValidateToken validates a CSRF token against stored secret
func (r *SQLiteRepository) ValidateToken(token, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT secret FROM csrf_tokens
		WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
	`

	var storedSecret string
	err := r.db.QueryRowContext(ctx, query, token).Scan(&storedSecret)

	if err == sql.ErrNoRows {
		return false, domain.ErrCSRFTokenInvalid
	}
	if err != nil {
		return false, err
	}

	if storedSecret != secret {
		return false, domain.ErrCSRFMismatch
	}

	return true, nil
}

// DeleteToken deletes a CSRF token
func (r *SQLiteRepository) DeleteToken(token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `DELETE FROM csrf_tokens WHERE token = ?`
	_, err := r.db.ExecContext(ctx, query, token)
	return err
}

// CleanupExpired removes all expired CSRF tokens
func (r *SQLiteRepository) CleanupExpired() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `DELETE FROM csrf_tokens WHERE expires_at <= CURRENT_TIMESTAMP`
	_, err := r.db.ExecContext(ctx, query)
	return err
}
