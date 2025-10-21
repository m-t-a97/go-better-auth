package repository

import (
	"context"
	"database/sql"

	"github.com/m-t-a97/go-better-auth/domain"
)

type PostgresUserRepository struct {
	db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Name, user.Email, user.EmailVerified, user.Image, user.CreatedAt, user.UpdatedAt)

	return err
}

func (r *PostgresUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users WHERE id = $1
	`

	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Name, &user.Email, &user.EmailVerified, &user.Image, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}

	return user, err
}

func (r *PostgresUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users WHERE email = $1
	`

	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Name, &user.Email, &user.EmailVerified, &user.Image, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}

	return user, err
}

func (r *PostgresUserRepository) Update(ctx context.Context, user *domain.User) error {
	query := `
		UPDATE users 
		SET name = $1, email = $2, email_verified = $3, image = $4, updated_at = $5
		WHERE id = $6
	`

	_, err := r.db.ExecContext(ctx, query,
		user.Name, user.Email, user.EmailVerified, user.Image, user.UpdatedAt, user.ID)

	return err
}

func (r *PostgresUserRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}
