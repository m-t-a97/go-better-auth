package postgres

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
)

// SessionRepository implements session.Repository for PostgreSQL
type SessionRepository struct {
	db         *sql.DB
	logQueries bool
}

// NewSessionRepository creates a new PostgreSQL session repository
func NewSessionRepository(db *sql.DB, logQueries bool) *SessionRepository {
	return &SessionRepository{
		db:         db,
		logQueries: logQueries,
	}
}

// Create creates a new session
func (r *SessionRepository) Create(s *session.Session) error {
	if s == nil {
		return fmt.Errorf("session cannot be nil")
	}

	query := `
		INSERT INTO sessions (id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.db.Exec(query, s.ID, s.UserID, s.ExpiresAt, s.Token, s.IPAddress, s.UserAgent, s.CreatedAt, s.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// FindByID retrieves a session by ID
func (r *SessionRepository) FindByID(id string) (*session.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions
		WHERE id = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var s session.Session
	err := r.db.QueryRow(query, id).Scan(
		&s.ID, &s.UserID, &s.ExpiresAt, &s.Token, &s.IPAddress, &s.UserAgent,
		&s.CreatedAt, &s.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query session: %w", err)
	}

	return &s, nil
}

// FindByToken retrieves a session by token
func (r *SessionRepository) FindByToken(token string) (*session.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions
		WHERE token = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var s session.Session
	err := r.db.QueryRow(query, token).Scan(
		&s.ID, &s.UserID, &s.ExpiresAt, &s.Token, &s.IPAddress, &s.UserAgent,
		&s.CreatedAt, &s.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query session: %w", err)
	}

	return &s, nil
}

// FindByUserID retrieves sessions by user ID
func (r *SessionRepository) FindByUserID(userID string) ([]*session.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*session.Session
	for rows.Next() {
		var s session.Session
		err := rows.Scan(
			&s.ID, &s.UserID, &s.ExpiresAt, &s.Token, &s.IPAddress, &s.UserAgent,
			&s.CreatedAt, &s.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, &s)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return sessions, nil
}

// Update updates an existing session
func (r *SessionRepository) Update(s *session.Session) error {
	if s == nil {
		return fmt.Errorf("session cannot be nil")
	}

	query := `
		UPDATE sessions
		SET user_id = $1, expires_at = $2, token = $3, ip_address = $4, user_agent = $5, updated_at = $6
		WHERE id = $7
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, s.UserID, s.ExpiresAt, s.Token, s.IPAddress, s.UserAgent, s.UpdatedAt, s.ID)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// Delete deletes a session by ID
func (r *SessionRepository) Delete(id string) error {
	query := `DELETE FROM sessions WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// DeleteByUserID deletes all sessions for a user
func (r *SessionRepository) DeleteByUserID(userID string) error {
	query := `DELETE FROM sessions WHERE user_id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete sessions: %w", err)
	}

	return nil
}

// DeleteExpired deletes all expired sessions
func (r *SessionRepository) DeleteExpired() error {
	query := `DELETE FROM sessions WHERE expires_at < $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.db.Exec(query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	return nil
}

// Count returns the total number of sessions
func (r *SessionRepository) Count() (int, error) {
	query := `SELECT COUNT(*) FROM sessions`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count sessions: %w", err)
	}

	return count, nil
}

// ExistsByID checks if a session exists by ID
func (r *SessionRepository) ExistsByID(id string) (bool, error) {
	query := `SELECT COUNT(*) FROM sessions WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByToken checks if a session exists by token
func (r *SessionRepository) ExistsByToken(token string) (bool, error) {
	query := `SELECT COUNT(*) FROM sessions WHERE token = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, token).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}

	return count > 0, nil
}
