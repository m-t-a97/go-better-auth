package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

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
