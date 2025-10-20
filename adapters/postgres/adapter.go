package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

// PostgresAdapter implements database repositories using PostgreSQL
type PostgresAdapter struct {
	db *sql.DB
}

// NewPostgresAdapter creates a new PostgreSQL adapter
func NewPostgresAdapter(connectionString string) (*PostgresAdapter, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresAdapter{db: db}, nil
}

// Close closes the database connection
func (a *PostgresAdapter) Close() error {
	return a.db.Close()
}

// UserRepository implementation

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

// SessionRepository implementation

type PostgresSessionRepository struct {
	db *sql.DB
}

func NewPostgresSessionRepository(db *sql.DB) *PostgresSessionRepository {
	return &PostgresSessionRepository{db: db}
}

func (r *PostgresSessionRepository) Create(ctx context.Context, session *domain.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.ExecContext(ctx, query,
		session.ID, session.UserID, session.ExpiresAt, session.Token,
		session.IPAddress, session.UserAgent, session.CreatedAt, session.UpdatedAt)

	return err
}

func (r *PostgresSessionRepository) FindByToken(ctx context.Context, token string) (*domain.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions WHERE token = $1
	`

	session := &domain.Session{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID, &session.UserID, &session.ExpiresAt, &session.Token,
		&session.IPAddress, &session.UserAgent, &session.CreatedAt, &session.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, domain.ErrInvalidToken
	}

	return session, err
}

func (r *PostgresSessionRepository) FindByUserID(ctx context.Context, userID string) ([]*domain.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions WHERE user_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*domain.Session
	for rows.Next() {
		session := &domain.Session{}
		err := rows.Scan(
			&session.ID, &session.UserID, &session.ExpiresAt, &session.Token,
			&session.IPAddress, &session.UserAgent, &session.CreatedAt, &session.UpdatedAt)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (r *PostgresSessionRepository) Update(ctx context.Context, session *domain.Session) error {
	query := `
		UPDATE sessions 
		SET expires_at = $1, updated_at = $2
		WHERE id = $3
	`

	_, err := r.db.ExecContext(ctx, query, session.ExpiresAt, session.UpdatedAt, session.ID)
	return err
}

func (r *PostgresSessionRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM sessions WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PostgresSessionRepository) DeleteByToken(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE token = $1`
	_, err := r.db.ExecContext(ctx, query, token)
	return err
}

func (r *PostgresSessionRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < $1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}

// AccountRepository implementation

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

// VerificationRepository implementation

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

// Migration SQL

const PostgresMigrationSQL = `
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    image TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    token VARCHAR(512) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

CREATE TABLE IF NOT EXISTS accounts (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    id_token TEXT,
    access_token_expires_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    scope TEXT,
    password TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(provider_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_provider_account ON accounts(provider_id, account_id);

CREATE TABLE IF NOT EXISTS verifications (
    id VARCHAR(255) PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    value VARCHAR(512) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verifications_identifier ON verifications(identifier);
CREATE INDEX IF NOT EXISTS idx_verifications_value ON verifications(value);
`
