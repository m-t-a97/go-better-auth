package adapter

import (
	"context"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
)

// Adapter defines the interface for database adapters
type Adapter interface {
	// Health checks
	HealthCheck(ctx context.Context) error

	// User repository
	UserRepository() user.Repository

	// Session repository
	SessionRepository() session.Repository

	// Account repository
	AccountRepository() account.Repository

	// Verification repository
	VerificationRepository() verification.Repository

	// Transaction support
	BeginTx(ctx context.Context) (Transaction, error)

	Close() error
}

// Transaction defines the interface for database transactions
type Transaction interface {
	// Commit commits the transaction
	Commit() error

	// Rollback rolls back the transaction
	Rollback() error

	// Repositories within transaction context
	UserRepository() user.Repository
	SessionRepository() session.Repository
	AccountRepository() account.Repository
	VerificationRepository() verification.Repository
}

// Config holds common database configuration
type Config struct {
	// Connection string (DSN)
	DSN string

	// Connection pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime int // seconds

	// Logging
	LogQueries bool

	// Migration
	AutoMigrate bool
}
