package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/m-t-a97/go-better-auth/adapter"
	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
)

// SQLiteAdapter implements database repositories using SQLite
type SQLiteAdapter struct {
	db               *sql.DB
	userRepo         *UserRepository
	sessionRepo      *SessionRepository
	accountRepo      *AccountRepository
	verificationRepo *VerificationRepository
	maxOpenConns     int
	maxIdleConns     int
	connMaxLifetime  time.Duration
	autoMigrate      bool
	logQueries       bool
}

// NewSQLiteAdapter creates a new SQLite adapter
func NewSQLiteAdapter(cfg *adapter.Config) (*SQLiteAdapter, error) {
	if cfg.DSN == "" {
		cfg.DSN = "file::memory:?cache=shared"
	}

	db, err := sql.Open("sqlite3", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	maxOpenConns := cfg.MaxOpenConns
	if maxOpenConns == 0 {
		maxOpenConns = 25
	}
	maxIdleConns := cfg.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 5
	}
	connMaxLifetime := time.Duration(cfg.ConnMaxLifetime) * time.Second
	if connMaxLifetime == 0 {
		connMaxLifetime = time.Hour
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	// Enable foreign keys for SQLite
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	a := &SQLiteAdapter{
		db:              db,
		maxOpenConns:    maxOpenConns,
		maxIdleConns:    maxIdleConns,
		connMaxLifetime: connMaxLifetime,
		autoMigrate:     cfg.AutoMigrate,
		logQueries:      cfg.LogQueries,
	}

	// Initialize repositories
	a.userRepo = NewUserRepository(db, cfg.LogQueries)
	a.sessionRepo = NewSessionRepository(db, cfg.LogQueries)
	a.accountRepo = NewAccountRepository(db, cfg.LogQueries)
	a.verificationRepo = NewVerificationRepository(db, cfg.LogQueries)

	// Auto-migrate if configured
	if cfg.AutoMigrate {
		if err := a.migrate(); err != nil {
			return nil, fmt.Errorf("migration failed: %w", err)
		}
	}

	return a, nil
}

// HealthCheck checks the database connection
func (a *SQLiteAdapter) HealthCheck(ctx context.Context) error {
	if err := a.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}

// Close closes the database connection
func (a *SQLiteAdapter) Close() error {
	return a.db.Close()
}

// GetDB returns the underlying database connection for advanced usage
func (a *SQLiteAdapter) GetDB() *sql.DB {
	return a.db
}

// UserRepository returns the user repository
func (a *SQLiteAdapter) UserRepository() user.Repository {
	return a.userRepo
}

// SessionRepository returns the session repository
func (a *SQLiteAdapter) SessionRepository() session.Repository {
	return a.sessionRepo
}

// AccountRepository returns the account repository
func (a *SQLiteAdapter) AccountRepository() account.Repository {
	return a.accountRepo
}

// VerificationRepository returns the verification repository
func (a *SQLiteAdapter) VerificationRepository() verification.Repository {
	return a.verificationRepo
}

// BeginTx begins a new transaction
func (a *SQLiteAdapter) BeginTx(ctx context.Context) (adapter.Transaction, error) {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &SQLiteTransaction{
		tx:         tx,
		logQueries: a.logQueries,
	}, nil
}

// migrate runs database migrations
func (a *SQLiteAdapter) migrate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := a.db.ExecContext(ctx, sqliteMigrationSQL); err != nil {
		return fmt.Errorf("failed to execute migrations: %w", err)
	}

	return nil
}

const sqliteMigrationSQL = `
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
    token VARCHAR(512) NOT NULL,
    type VARCHAR(50) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verifications_identifier ON verifications(identifier);
CREATE INDEX IF NOT EXISTS idx_verifications_token ON verifications(token);
CREATE INDEX IF NOT EXISTS idx_verifications_type ON verifications(type);
`
