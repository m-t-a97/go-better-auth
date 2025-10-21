package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

type PostgresVerificationRepository struct {
	db *sql.DB
}

func NewPostgresVerificationRepository(db *sql.DB) *PostgresVerificationRepository {
	return &PostgresVerificationRepository{db: db}
}

func (r *PostgresVerificationRepository) Create(ctx context.Context, verification *domain.Verification) error {
	query := `
		INSERT INTO verifications (id, identifier, value, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.ExecContext(ctx, query,
		verification.ID, verification.Identifier, verification.Value,
		verification.ExpiresAt, verification.CreatedAt)

	return err
}

func (r *PostgresVerificationRepository) FindByIdentifierAndValue(ctx context.Context, identifier, value string) (*domain.Verification, error) {
	var query string
	var args []any

	if identifier == "" {
		// Search by value only
		query = `
			SELECT id, identifier, value, expires_at, created_at
			FROM verifications WHERE value = $1
		`
		args = []any{value}
	} else {
		query = `
			SELECT id, identifier, value, expires_at, created_at
			FROM verifications WHERE identifier = $1 AND value = $2
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

func (r *PostgresVerificationRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM verifications WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PostgresVerificationRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM verifications WHERE expires_at < $1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}
