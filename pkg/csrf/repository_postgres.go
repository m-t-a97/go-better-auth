package csrf

import (
	"context"
	"database/sql"
	"time"

	"github.com/m-t-a97/go-better-auth/internal/domain"
)

// PostgresRepository is a PostgreSQL implementation of CSRFRepository
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL CSRF repository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// InitSchema initializes the CSRF tokens table
func (r *PostgresRepository) InitSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS csrf_tokens (
			id SERIAL PRIMARY KEY,
			token VARCHAR(255) UNIQUE NOT NULL,
			secret VARCHAR(255) NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_expires_at (expires_at),
			INDEX idx_token (token)
		)
	`

	_, err := r.db.ExecContext(ctx, schema)
	return err
}

// StoreToken stores a CSRF token and its secret
func (r *PostgresRepository) StoreToken(token, secret string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO csrf_tokens (token, secret, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (token) DO UPDATE SET
			secret = $2,
			expires_at = $3
	`

	_, err := r.db.ExecContext(ctx, query, token, secret, expiresAt)
	return err
}

// ValidateToken validates a CSRF token against stored secret
func (r *PostgresRepository) ValidateToken(token, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT secret FROM csrf_tokens
		WHERE token = $1 AND expires_at > NOW()
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
func (r *PostgresRepository) DeleteToken(token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `DELETE FROM csrf_tokens WHERE token = $1`
	_, err := r.db.ExecContext(ctx, query, token)
	return err
}

// CleanupExpired removes all expired CSRF tokens
func (r *PostgresRepository) CleanupExpired() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `DELETE FROM csrf_tokens WHERE expires_at <= NOW()`
	_, err := r.db.ExecContext(ctx, query)
	return err
}
