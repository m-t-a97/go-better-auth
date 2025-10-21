package repository

import (
	"context"
	"database/sql"

	"github.com/m-t-a97/go-better-auth/domain"
)

type PostgresAccountRepository struct {
	db *sql.DB
}

func NewPostgresAccountRepository(db *sql.DB) *PostgresAccountRepository {
	return &PostgresAccountRepository{db: db}
}

func (r *PostgresAccountRepository) Create(ctx context.Context, account *domain.Account) error {
	query := `
		INSERT INTO accounts (id, user_id, account_id, provider_id, access_token, refresh_token, 
		                      id_token, access_token_expires_at, refresh_token_expires_at, scope, 
		                      password, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := r.db.ExecContext(ctx, query,
		account.ID, account.UserID, account.AccountID, account.ProviderId,
		account.AccessToken, account.RefreshToken, account.IDToken,
		account.AccessTokenExpiresAt, account.RefreshTokenExpiresAt,
		account.Scope, account.Password, account.CreatedAt, account.UpdatedAt)

	return err
}

func (r *PostgresAccountRepository) FindByUserIDAndProvider(ctx context.Context, userID, providerID string) (*domain.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, 
		       id_token, access_token_expires_at, refresh_token_expires_at, scope, 
		       password, created_at, updated_at
		FROM accounts WHERE user_id = $1 AND provider_id = $2
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

func (r *PostgresAccountRepository) FindByProviderAccountID(ctx context.Context, providerID, accountID string) (*domain.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, 
		       id_token, access_token_expires_at, refresh_token_expires_at, scope, 
		       password, created_at, updated_at
		FROM accounts WHERE provider_id = $1 AND account_id = $2
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

func (r *PostgresAccountRepository) Update(ctx context.Context, account *domain.Account) error {
	query := `
		UPDATE accounts 
		SET access_token = $1, refresh_token = $2, id_token = $3, 
		    access_token_expires_at = $4, refresh_token_expires_at = $5, 
		    scope = $6, password = $7, updated_at = $8
		WHERE id = $9
	`

	_, err := r.db.ExecContext(ctx, query,
		account.AccessToken, account.RefreshToken, account.IDToken,
		account.AccessTokenExpiresAt, account.RefreshTokenExpiresAt,
		account.Scope, account.Password, account.UpdatedAt, account.ID)

	return err
}

func (r *PostgresAccountRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM accounts WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PostgresAccountRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, 
		       id_token, access_token_expires_at, refresh_token_expires_at, scope, 
		       password, created_at, updated_at
		FROM accounts WHERE user_id = $1
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
