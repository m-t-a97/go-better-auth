package repository

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/m-t-a97/go-better-auth/domain"
)

type SQLiteVerificationRepository struct {
	db *sql.DB
}

func NewSQLiteVerificationRepository(db *sql.DB) *SQLiteVerificationRepository {
	return &SQLiteVerificationRepository{db: db}
}

func (r *SQLiteVerificationRepository) Create(ctx context.Context, verification *domain.Verification) error {
	query := `
		INSERT INTO verifications (id, identifier, value, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		verification.ID, verification.Identifier, verification.Value,
		verification.ExpiresAt, verification.CreatedAt)

	return err
}

func (r *SQLiteVerificationRepository) FindByIdentifierAndValue(ctx context.Context, identifier, value string) (*domain.Verification, error) {
	var query string
	var args []any

	if identifier == "" {
		// Search by value only
		query = `
			SELECT id, identifier, value, expires_at, created_at
			FROM verifications WHERE value = ?
		`
		args = []any{value}
	} else {
		query = `
			SELECT id, identifier, value, expires_at, created_at
			FROM verifications WHERE identifier = ? AND value = ?
		`
		args = []any{identifier, value}
	}

	verification := &domain.Verification{}
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&verification.ID, &verification.Identifier, &verification.Value,
		&verification.ExpiresAt, &verification.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, domain.ErrInvalidToken
	}

	return verification, err
}

func (r *SQLiteVerificationRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM verifications WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *SQLiteVerificationRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM verifications WHERE expires_at < ?`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}
