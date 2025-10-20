package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteAdapter implements database repositories using SQLite
type SQLiteAdapter struct {
	db *sql.DB
}

// NewSQLiteAdapter creates a new SQLite adapter
func NewSQLiteAdapter(connectionString string) (*SQLiteAdapter, error) {
	db, err := sql.Open("sqlite3", connectionString)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Enable foreign keys for SQLite
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}

	return &SQLiteAdapter{db: db}, nil
}

// Close closes the database connection
func (a *SQLiteAdapter) Close() error {
	return a.db.Close()
}

// GetDB returns the underlying database connection for advanced usage
func (a *SQLiteAdapter) GetDB() *sql.DB {
	return a.db
}

// UserRepository implementation

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

// SessionRepository implementation

type SQLiteSessionRepository struct {
	db *sql.DB
}

func NewSQLiteSessionRepository(db *sql.DB) *SQLiteSessionRepository {
	return &SQLiteSessionRepository{db: db}
}

func (r *SQLiteSessionRepository) Create(ctx context.Context, session *domain.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		session.ID, session.UserID, session.ExpiresAt, session.Token,
		session.IPAddress, session.UserAgent, session.CreatedAt, session.UpdatedAt)

	return err
}

func (r *SQLiteSessionRepository) FindByToken(ctx context.Context, token string) (*domain.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions WHERE token = ?
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

func (r *SQLiteSessionRepository) FindByUserID(ctx context.Context, userID string) ([]*domain.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions WHERE user_id = ?
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

func (r *SQLiteSessionRepository) Update(ctx context.Context, session *domain.Session) error {
	query := `
		UPDATE sessions 
		SET expires_at = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := r.db.ExecContext(ctx, query, session.ExpiresAt, session.UpdatedAt, session.ID)
	return err
}

func (r *SQLiteSessionRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM sessions WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *SQLiteSessionRepository) DeleteByToken(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := r.db.ExecContext(ctx, query, token)
	return err
}

func (r *SQLiteSessionRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < ?`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}

// AccountRepository implementation

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

// VerificationRepository implementation

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
	var args []interface{}

	if identifier == "" {
		// Search by value only
		query = `
			SELECT id, identifier, value, expires_at, created_at
			FROM verifications WHERE value = ?
		`
		args = []interface{}{value}
	} else {
		query = `
			SELECT id, identifier, value, expires_at, created_at
			FROM verifications WHERE identifier = ? AND value = ?
		`
		args = []interface{}{identifier, value}
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

// Migration SQL

const SQLiteMigrationSQL = `
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT 0,
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
