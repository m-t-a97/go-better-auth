package repository

import (
	"context"
	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	"github.com/m-t-a97/go-better-auth/domain"
)

type SQLiteAccountRepository struct {
	db *sql.DB
}

func NewSQLiteAccountRepository(db *sql.DB) *SQLiteAccountRepository {
	return &SQLiteAccountRepository{db: db}
}

func (r *SQLiteAccountRepository) Create(ctx context.Context, account *domain.Account) error {
	query := `
		INSERT INTO accounts (id, user_id, account_id, provider_id, access_token, refresh_token, 
		                      id_token, access_token_expires_at, refresh_token_expires_at, scope, 
		                      password, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		account.ID, account.UserID, account.AccountID, account.ProviderId,
		account.AccessToken, account.RefreshToken, account.IDToken,
		account.AccessTokenExpiresAt, account.RefreshTokenExpiresAt,
		account.Scope, account.Password, account.CreatedAt, account.UpdatedAt)

	return err
}

func (r *SQLiteAccountRepository) FindByUserIDAndProvider(ctx context.Context, userID, providerID string) (*domain.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, 
		       id_token, access_token_expires_at, refresh_token_expires_at, scope, 
		       password, created_at, updated_at
		FROM accounts WHERE user_id = ? AND provider_id = ?
	`

	account := &domain.Account{}
	err := r.db.QueryRowContext(ctx, query, userID, providerID).Scan(
		&account.ID, &account.UserID, &account.AccountID, &account.ProviderId,
		&account.AccessToken, &account.RefreshToken, &account.IDToken,
		&account.AccessTokenExpiresAt, &account.RefreshTokenExpiresAt,
		&account.Scope, &account.Password, &account.CreatedAt, &account.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}

	return account, err
}

func (r *SQLiteAccountRepository) FindByProviderAccountID(ctx context.Context, providerID, accountID string) (*domain.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, 
		       id_token, access_token_expires_at, refresh_token_expires_at, scope, 
		       password, created_at, updated_at
		FROM accounts WHERE provider_id = ? AND account_id = ?
	`

	account := &domain.Account{}
	err := r.db.QueryRowContext(ctx, query, providerID, accountID).Scan(
		&account.ID, &account.UserID, &account.AccountID, &account.ProviderId,
		&account.AccessToken, &account.RefreshToken, &account.IDToken,
		&account.AccessTokenExpiresAt, &account.RefreshTokenExpiresAt,
		&account.Scope, &account.Password, &account.CreatedAt, &account.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}

	return account, err
}

func (r *SQLiteAccountRepository) Update(ctx context.Context, account *domain.Account) error {
	query := `
		UPDATE accounts 
		SET access_token = ?, refresh_token = ?, id_token = ?, 
		    access_token_expires_at = ?, refresh_token_expires_at = ?, 
		    scope = ?, password = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := r.db.ExecContext(ctx, query,
		account.AccessToken, account.RefreshToken, account.IDToken,
		account.AccessTokenExpiresAt, account.RefreshTokenExpiresAt,
		account.Scope, account.Password, account.UpdatedAt, account.ID)

	return err
}

func (r *SQLiteAccountRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM accounts WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *SQLiteAccountRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, 
		       id_token, access_token_expires_at, refresh_token_expires_at, scope, 
		       password, created_at, updated_at
		FROM accounts WHERE user_id = ?
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*domain.Account
	for rows.Next() {
		account := &domain.Account{}
		err := rows.Scan(
			&account.ID, &account.UserID, &account.AccountID, &account.ProviderId,
			&account.AccessToken, &account.RefreshToken, &account.IDToken,
			&account.AccessTokenExpiresAt, &account.RefreshTokenExpiresAt,
			&account.Scope, &account.Password, &account.CreatedAt, &account.UpdatedAt)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}

	return accounts, nil
}
