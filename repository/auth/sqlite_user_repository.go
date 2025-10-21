package repository

import (
	"context"
	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	"github.com/m-t-a97/go-better-auth/domain"
)

type SQLiteUserRepository struct {
	db *sql.DB
}

func NewSQLiteUserRepository(db *sql.DB) *SQLiteUserRepository {
	return &SQLiteUserRepository{db: db}
}

func (r *SQLiteUserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Name, user.Email, user.EmailVerified, user.Image, user.CreatedAt, user.UpdatedAt)

	return err
}

func (r *SQLiteUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users WHERE id = ?
	`

	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Name, &user.Email, &user.EmailVerified, &user.Image, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}

	return user, err
}

func (r *SQLiteUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users WHERE email = ?
	`

	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Name, &user.Email, &user.EmailVerified, &user.Image, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}

	return user, err
}

func (r *SQLiteUserRepository) Update(ctx context.Context, user *domain.User) error {
	query := `
		UPDATE users 
		SET name = ?, email = ?, email_verified = ?, image = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := r.db.ExecContext(ctx, query,
		user.Name, user.Email, user.EmailVerified, user.Image, user.UpdatedAt, user.ID)

	return err
}

func (r *SQLiteUserRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}
