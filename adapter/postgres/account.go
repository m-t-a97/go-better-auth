package postgres

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/m-t-a97/go-better-auth/domain/account"
)

// AccountRepository implements account.Repository for PostgreSQL
type AccountRepository struct {
	db         *sql.DB
	logQueries bool
}

// NewAccountRepository creates a new PostgreSQL account repository
func NewAccountRepository(db *sql.DB, logQueries bool) *AccountRepository {
	return &AccountRepository{
		db:         db,
		logQueries: logQueries,
	}
}

// Create creates a new account
func (r *AccountRepository) Create(a *account.Account) error {
	if a == nil {
		return fmt.Errorf("account cannot be nil")
	}

	query := `
		INSERT INTO accounts (id, user_id, account_id, provider_id, access_token, refresh_token, id_token,
			access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.db.Exec(query, a.ID, a.UserID, a.AccountID, a.ProviderID, a.AccessToken, a.RefreshToken,
		a.IDToken, a.AccessTokenExpiresAt, a.RefreshTokenExpiresAt, a.Scope, a.Password, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create account: %w", err)
	}

	return nil
}

// FindByID retrieves an account by ID
func (r *AccountRepository) FindByID(id string) (*account.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, id_token,
			access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at
		FROM accounts
		WHERE id = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var a account.Account
	err := r.db.QueryRow(query, id).Scan(
		&a.ID, &a.UserID, &a.AccountID, &a.ProviderID, &a.AccessToken, &a.RefreshToken, &a.IDToken,
		&a.AccessTokenExpiresAt, &a.RefreshTokenExpiresAt, &a.Scope, &a.Password, &a.CreatedAt, &a.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("account not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	return &a, nil
}

// FindByUserIDAndProvider retrieves a user's account for a specific provider
func (r *AccountRepository) FindByUserIDAndProvider(userID string, providerID account.ProviderType) (*account.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, id_token,
			access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at
		FROM accounts
		WHERE user_id = $1 AND provider_id = $2
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var a account.Account
	err := r.db.QueryRow(query, userID, providerID).Scan(
		&a.ID, &a.UserID, &a.AccountID, &a.ProviderID, &a.AccessToken, &a.RefreshToken, &a.IDToken,
		&a.AccessTokenExpiresAt, &a.RefreshTokenExpiresAt, &a.Scope, &a.Password, &a.CreatedAt, &a.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("account not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	return &a, nil
}

// FindByUserID retrieves all accounts for a user
func (r *AccountRepository) FindByUserID(userID string) ([]*account.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, id_token,
			access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at
		FROM accounts
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*account.Account
	for rows.Next() {
		var a account.Account
		err := rows.Scan(
			&a.ID, &a.UserID, &a.AccountID, &a.ProviderID, &a.AccessToken, &a.RefreshToken, &a.IDToken,
			&a.AccessTokenExpiresAt, &a.RefreshTokenExpiresAt, &a.Scope, &a.Password, &a.CreatedAt, &a.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan account: %w", err)
		}
		accounts = append(accounts, &a)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return accounts, nil
}

// Update updates an existing account
func (r *AccountRepository) Update(a *account.Account) error {
	if a == nil {
		return fmt.Errorf("account cannot be nil")
	}

	query := `
		UPDATE accounts
		SET user_id = $1, account_id = $2, provider_id = $3, access_token = $4, refresh_token = $5, id_token = $6,
			access_token_expires_at = $7, refresh_token_expires_at = $8, scope = $9, password = $10, updated_at = $11
		WHERE id = $12
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, a.UserID, a.AccountID, a.ProviderID, a.AccessToken, a.RefreshToken,
		a.IDToken, a.AccessTokenExpiresAt, a.RefreshTokenExpiresAt, a.Scope, a.Password, a.UpdatedAt, a.ID)
	if err != nil {
		return fmt.Errorf("failed to update account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

// Delete deletes an account by ID
func (r *AccountRepository) Delete(id string) error {
	query := `DELETE FROM accounts WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

// DeleteByUserID deletes all accounts for a user
func (r *AccountRepository) DeleteByUserID(userID string) error {
	query := `DELETE FROM accounts WHERE user_id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete accounts: %w", err)
	}

	return nil
}

// Count returns the total number of accounts
func (r *AccountRepository) Count() (int, error) {
	query := `SELECT COUNT(*) FROM accounts`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count accounts: %w", err)
	}

	return count, nil
}

// ExistsByID checks if an account exists by ID
func (r *AccountRepository) ExistsByID(id string) (bool, error) {
	query := `SELECT COUNT(*) FROM accounts WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check account existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByUserIDAndProvider checks if a user has an account with the specified provider
func (r *AccountRepository) ExistsByUserIDAndProvider(userID string, providerID account.ProviderType) (bool, error) {
	query := `SELECT COUNT(*) FROM accounts WHERE user_id = $1 AND provider_id = $2`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, userID, providerID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check account existence: %w", err)
	}

	return count > 0, nil
}
