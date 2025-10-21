package postgres

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/m-t-a97/go-better-auth/domain/user"
)

// UserRepository implements user.Repository for PostgreSQL
type UserRepository struct {
	db         *sql.DB
	logQueries bool
}

// NewUserRepository creates a new PostgreSQL user repository
func NewUserRepository(db *sql.DB, logQueries bool) *UserRepository {
	return &UserRepository{
		db:         db,
		logQueries: logQueries,
	}
}

// Create creates a new user
func (r *UserRepository) Create(u *user.User) error {
	if u == nil {
		return fmt.Errorf("user cannot be nil")
	}

	query := `
		INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.db.Exec(query, u.ID, u.Name, u.Email, u.EmailVerified, u.Image, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// FindByID retrieves a user by ID
func (r *UserRepository) FindByID(id string) (*user.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var u user.User
	err := r.db.QueryRow(query, id).Scan(
		&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image,
		&u.CreatedAt, &u.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	return &u, nil
}

// FindByEmail retrieves a user by email
func (r *UserRepository) FindByEmail(email string) (*user.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var u user.User
	err := r.db.QueryRow(query, email).Scan(
		&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image,
		&u.CreatedAt, &u.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	return &u, nil
}

// Update updates an existing user
func (r *UserRepository) Update(u *user.User) error {
	if u == nil {
		return fmt.Errorf("user cannot be nil")
	}

	query := `
		UPDATE users
		SET name = $1, email = $2, email_verified = $3, image = $4, updated_at = $5
		WHERE id = $6
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, u.Name, u.Email, u.EmailVerified, u.Image, u.UpdatedAt, u.ID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// Delete deletes a user by ID
func (r *UserRepository) Delete(id string) error {
	query := `DELETE FROM users WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// List retrieves users with pagination
func (r *UserRepository) List(offset int, limit int) ([]*user.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*user.User
	for rows.Next() {
		var u user.User
		err := rows.Scan(
			&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image,
			&u.CreatedAt, &u.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, &u)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return users, nil
}

// Count returns the total number of users
func (r *UserRepository) Count() (int, error) {
	query := `SELECT COUNT(*) FROM users`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// ExistsByEmail checks if a user exists by email
func (r *UserRepository) ExistsByEmail(email string) (bool, error) {
	query := `SELECT COUNT(*) FROM users WHERE email = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, email).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByID checks if a user exists by ID
func (r *UserRepository) ExistsByID(id string) (bool, error) {
	query := `SELECT COUNT(*) FROM users WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return count > 0, nil
}
