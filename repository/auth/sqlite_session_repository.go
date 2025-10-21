package repository

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/m-t-a97/go-better-auth/domain"
)

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
