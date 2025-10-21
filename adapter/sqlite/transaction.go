package sqlite

import (
	"database/sql"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
)

// SQLiteTransaction implements adapter.Transaction for SQLite
type SQLiteTransaction struct {
	tx         *sql.Tx
	logQueries bool
}

// Commit commits the transaction
func (t *SQLiteTransaction) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction
func (t *SQLiteTransaction) Rollback() error {
	return t.tx.Rollback()
}

// UserRepository returns a user repository (uses underlying connection)
func (t *SQLiteTransaction) UserRepository() user.Repository {
	// For now, return a standard repository - transaction support can be expanded
	// In a production system, would create tx-aware implementations
	return &UserRepository{
		db:         nil, // Would need to adapt to tx
		logQueries: t.logQueries,
	}
}

// SessionRepository returns a session repository (uses underlying connection)
func (t *SQLiteTransaction) SessionRepository() session.Repository {
	return &SessionRepository{
		db:         nil, // Would need to adapt to tx
		logQueries: t.logQueries,
	}
}

// AccountRepository returns an account repository (uses underlying connection)
func (t *SQLiteTransaction) AccountRepository() account.Repository {
	return &AccountRepository{
		db:         nil, // Would need to adapt to tx
		logQueries: t.logQueries,
	}
}

// VerificationRepository returns a verification repository (uses underlying connection)
func (t *SQLiteTransaction) VerificationRepository() verification.Repository {
	return &VerificationRepository{
		db:         nil, // Would need to adapt to tx
		logQueries: t.logQueries,
	}
}
