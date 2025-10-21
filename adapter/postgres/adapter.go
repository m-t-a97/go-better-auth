package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	"github.com/m-t-a97/go-better-auth/adapter"
	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
)

// PostgresAdapter implements adapter.Adapter using PostgreSQL
type PostgresAdapter struct {
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

// NewPostgresAdapter creates a new PostgreSQL adapter
func NewPostgresAdapter(cfg *adapter.Config) (*PostgresAdapter, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("DSN is required for PostgreSQL adapter")
	}

	db, err := sql.Open("postgres", cfg.DSN)
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

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	a := &PostgresAdapter{
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
func (a *PostgresAdapter) HealthCheck(ctx context.Context) error {
	if err := a.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}

// Close closes the database connection
func (a *PostgresAdapter) Close() error {
	return a.db.Close()
}

// GetDB returns the underlying database connection for advanced usage
func (a *PostgresAdapter) GetDB() *sql.DB {
	return a.db
}

// UserRepository returns the user repository
func (a *PostgresAdapter) UserRepository() user.Repository {
	return a.userRepo
}

// SessionRepository returns the session repository
func (a *PostgresAdapter) SessionRepository() session.Repository {
	return a.sessionRepo
}

// AccountRepository returns the account repository
func (a *PostgresAdapter) AccountRepository() account.Repository {
	return a.accountRepo
}

// VerificationRepository returns the verification repository
func (a *PostgresAdapter) VerificationRepository() verification.Repository {
	return a.verificationRepo
}

// BeginTx begins a new transaction
func (a *PostgresAdapter) BeginTx(ctx context.Context) (adapter.Transaction, error) {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return NewPostgresTransaction(tx, a.logQueries), nil
}

// migrate runs database migrations
func (a *PostgresAdapter) migrate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := a.db.ExecContext(ctx, postgresMigrationSQL); err != nil {
		return fmt.Errorf("failed to execute migrations: %w", err)
	}

	return nil
}

const postgresMigrationSQL = `
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
