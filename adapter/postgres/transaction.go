package postgres

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
)

// PostgresTransaction implements adapter.Transaction for PostgreSQL
type PostgresTransaction struct {
	tx               *sql.Tx
	logQueries       bool
	userRepo         *txUserRepository
	sessionRepo      *txSessionRepository
	accountRepo      *txAccountRepository
	verificationRepo *txVerificationRepository
}

// NewPostgresTransaction creates a new transaction for PostgreSQL
func NewPostgresTransaction(tx *sql.Tx, logQueries bool) *PostgresTransaction {
	return &PostgresTransaction{
		tx:         tx,
		logQueries: logQueries,
		userRepo: &txUserRepository{
			tx:         tx,
			logQueries: logQueries,
		},
		sessionRepo: &txSessionRepository{
			tx:         tx,
			logQueries: logQueries,
		},
		accountRepo: &txAccountRepository{
			tx:         tx,
			logQueries: logQueries,
		},
		verificationRepo: &txVerificationRepository{
			tx:         tx,
			logQueries: logQueries,
		},
	}
}

// Commit commits the transaction
func (t *PostgresTransaction) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction
func (t *PostgresTransaction) Rollback() error {
	return t.tx.Rollback()
}

// UserRepository returns a user repository that uses the transaction
func (t *PostgresTransaction) UserRepository() user.Repository {
	return t.userRepo
}

// SessionRepository returns a session repository that uses the transaction
func (t *PostgresTransaction) SessionRepository() session.Repository {
	return t.sessionRepo
}

// AccountRepository returns an account repository that uses the transaction
func (t *PostgresTransaction) AccountRepository() account.Repository {
	return t.accountRepo
}

// VerificationRepository returns a verification repository that uses the transaction
func (t *PostgresTransaction) VerificationRepository() verification.Repository {
	return t.verificationRepo
}

// --- Transaction-aware user repository ---

type txUserRepository struct {
	tx         *sql.Tx
	logQueries bool
}

func (r *txUserRepository) Create(u *user.User) error {
	if u == nil {
		return fmt.Errorf("user cannot be nil")
	}

	query := `
		INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.tx.Exec(query, u.ID, u.Name, u.Email, u.EmailVerified, u.Image, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (r *txUserRepository) FindByID(id string) (*user.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var u user.User
	err := r.tx.QueryRow(query, id).Scan(
		&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image,
		&u.CreatedAt, &u.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	return &u, nil
}

func (r *txUserRepository) FindByEmail(email string) (*user.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var u user.User
	err := r.tx.QueryRow(query, email).Scan(
		&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image,
		&u.CreatedAt, &u.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	return &u, nil
}

func (r *txUserRepository) Update(u *user.User) error {
	if u == nil {
		return fmt.Errorf("user cannot be nil")
	}

	query := `
		UPDATE users
		SET name = $1, email = $2, email_verified = $3, image = $4, updated_at = $5
		WHERE id = $6
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.tx.Exec(query, u.Name, u.Email, u.EmailVerified, u.Image, u.UpdatedAt, u.ID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

func (r *txUserRepository) Delete(id string) error {
	query := `DELETE FROM users WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.tx.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

func (r *txUserRepository) List(limit int, offset int) ([]*user.User, error) {
	query := `
		SELECT id, name, email, email_verified, image, created_at, updated_at
		FROM users
		LIMIT $1 OFFSET $2
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	rows, err := r.tx.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []*user.User
	for rows.Next() {
		var u user.User
		err := rows.Scan(
			&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image,
			&u.CreatedAt, &u.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, &u)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate users: %w", err)
	}

	return users, nil
}

func (r *txUserRepository) Count() (int, error) {
	query := `SELECT COUNT(*) FROM users`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.tx.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

func (r *txUserRepository) ExistsByEmail(email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var exists bool
	err := r.tx.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}

func (r *txUserRepository) ExistsByID(id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var exists bool
	err := r.tx.QueryRow(query, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}

// --- Transaction-aware session repository ---

type txSessionRepository struct {
	tx         *sql.Tx
	logQueries bool
}

func (r *txSessionRepository) Create(s *session.Session) error {
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

	_, err := r.tx.Exec(query, s.ID, s.UserID, s.ExpiresAt, s.Token, s.IPAddress, s.UserAgent, s.CreatedAt, s.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

func (r *txSessionRepository) FindByID(id string) (*session.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions
		WHERE id = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var s session.Session
	err := r.tx.QueryRow(query, id).Scan(
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

func (r *txSessionRepository) FindByToken(token string) (*session.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions
		WHERE token = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var s session.Session
	err := r.tx.QueryRow(query, token).Scan(
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

func (r *txSessionRepository) FindByUserID(userID string) ([]*session.Session, error) {
	query := `
		SELECT id, user_id, expires_at, token, ip_address, user_agent, created_at, updated_at
		FROM sessions
		WHERE user_id = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	rows, err := r.tx.Query(query, userID)
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
		return nil, fmt.Errorf("failed to iterate sessions: %w", err)
	}

	return sessions, nil
}

func (r *txSessionRepository) Update(s *session.Session) error {
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

	result, err := r.tx.Exec(query, s.UserID, s.ExpiresAt, s.Token, s.IPAddress, s.UserAgent, s.UpdatedAt, s.ID)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

func (r *txSessionRepository) Delete(id string) error {
	query := `DELETE FROM sessions WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.tx.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

func (r *txSessionRepository) DeleteByUserID(userID string) error {
	query := `DELETE FROM sessions WHERE user_id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.tx.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete sessions: %w", err)
	}

	return nil
}

func (r *txSessionRepository) DeleteExpired() error {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.tx.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	return nil
}

func (r *txSessionRepository) Count() (int, error) {
	query := `SELECT COUNT(*) FROM sessions`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.tx.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count sessions: %w", err)
	}

	return count, nil
}

func (r *txSessionRepository) ExistsByID(id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM sessions WHERE id = $1)`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var exists bool
	err := r.tx.QueryRow(query, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}

	return exists, nil
}

func (r *txSessionRepository) ExistsByToken(token string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM sessions WHERE token = $1)`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var exists bool
	err := r.tx.QueryRow(query, token).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}

	return exists, nil
}

// --- Transaction-aware account repository ---

type txAccountRepository struct {
	tx         *sql.Tx
	logQueries bool
}

func (r *txAccountRepository) Create(a *account.Account) error {
	if a == nil {
		return fmt.Errorf("account cannot be nil")
	}

	query := `
		INSERT INTO accounts (id, user_id, account_id, provider_id, access_token, refresh_token, 
			id_token, access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.tx.Exec(query, a.ID, a.UserID, a.AccountID, a.ProviderID, a.AccessToken,
		a.RefreshToken, a.IDToken, a.AccessTokenExpiresAt, a.RefreshTokenExpiresAt,
		a.Scope, a.Password, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create account: %w", err)
	}

	return nil
}

func (r *txAccountRepository) FindByID(id string) (*account.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, id_token,
			access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at
		FROM accounts
		WHERE id = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var a account.Account
	err := r.tx.QueryRow(query, id).Scan(
		&a.ID, &a.UserID, &a.AccountID, &a.ProviderID, &a.AccessToken,
		&a.RefreshToken, &a.IDToken, &a.AccessTokenExpiresAt, &a.RefreshTokenExpiresAt,
		&a.Scope, &a.Password, &a.CreatedAt, &a.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("account not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	return &a, nil
}

func (r *txAccountRepository) FindByUserIDAndProvider(userID string, providerID account.ProviderType) (*account.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, id_token,
			access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at
		FROM accounts
		WHERE user_id = $1 AND provider_id = $2
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var a account.Account
	err := r.tx.QueryRow(query, userID, string(providerID)).Scan(
		&a.ID, &a.UserID, &a.AccountID, &a.ProviderID, &a.AccessToken,
		&a.RefreshToken, &a.IDToken, &a.AccessTokenExpiresAt, &a.RefreshTokenExpiresAt,
		&a.Scope, &a.Password, &a.CreatedAt, &a.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("account not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	return &a, nil
}

func (r *txAccountRepository) FindByUserID(userID string) ([]*account.Account, error) {
	query := `
		SELECT id, user_id, account_id, provider_id, access_token, refresh_token, id_token,
			access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at
		FROM accounts
		WHERE user_id = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	rows, err := r.tx.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*account.Account
	for rows.Next() {
		var a account.Account
		var providerID string
		err := rows.Scan(
			&a.ID, &a.UserID, &a.AccountID, &providerID, &a.AccessToken,
			&a.RefreshToken, &a.IDToken, &a.AccessTokenExpiresAt, &a.RefreshTokenExpiresAt,
			&a.Scope, &a.Password, &a.CreatedAt, &a.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan account: %w", err)
		}
		a.ProviderID = account.ProviderType(providerID)
		accounts = append(accounts, &a)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate accounts: %w", err)
	}

	return accounts, nil
}

func (r *txAccountRepository) Update(a *account.Account) error {
	if a == nil {
		return fmt.Errorf("account cannot be nil")
	}

	query := `
		UPDATE accounts
		SET user_id = $1, account_id = $2, provider_id = $3, access_token = $4, refresh_token = $5,
			id_token = $6, access_token_expires_at = $7, refresh_token_expires_at = $8,
			scope = $9, password = $10, updated_at = $11
		WHERE id = $12
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.tx.Exec(query, a.UserID, a.AccountID, a.ProviderID, a.AccessToken,
		a.RefreshToken, a.IDToken, a.AccessTokenExpiresAt, a.RefreshTokenExpiresAt,
		a.Scope, a.Password, a.UpdatedAt, a.ID)
	if err != nil {
		return fmt.Errorf("failed to update account: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

func (r *txAccountRepository) Delete(id string) error {
	query := `DELETE FROM accounts WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.tx.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete account: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

func (r *txAccountRepository) DeleteByUserID(userID string) error {
	query := `DELETE FROM accounts WHERE user_id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.tx.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete accounts: %w", err)
	}

	return nil
}

func (r *txAccountRepository) Count() (int, error) {
	query := `SELECT COUNT(*) FROM accounts`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.tx.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count accounts: %w", err)
	}

	return count, nil
}

func (r *txAccountRepository) ExistsByID(id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1)`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var exists bool
	err := r.tx.QueryRow(query, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check account existence: %w", err)
	}

	return exists, nil
}

func (r *txAccountRepository) ExistsByUserIDAndProvider(userID string, providerID account.ProviderType) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM accounts WHERE user_id = $1 AND provider_id = $2)`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var exists bool
	err := r.tx.QueryRow(query, userID, string(providerID)).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check account existence: %w", err)
	}

	return exists, nil
}

// --- Transaction-aware verification repository ---

type txVerificationRepository struct {
	tx         *sql.Tx
	logQueries bool
}

func (r *txVerificationRepository) Create(v *verification.Verification) error {
	if v == nil {
		return fmt.Errorf("verification cannot be nil")
	}

	query := `
		INSERT INTO verifications (id, identifier, token, type, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.tx.Exec(query, v.ID, v.Identifier, v.Token, string(v.Type), v.ExpiresAt, v.CreatedAt, v.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create verification: %w", err)
	}

	return nil
}

func (r *txVerificationRepository) FindByToken(token string) (*verification.Verification, error) {
	query := `
		SELECT id, identifier, token, type, expires_at, created_at, updated_at
		FROM verifications
		WHERE token = $1
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var v verification.Verification
	var verType string
	err := r.tx.QueryRow(query, token).Scan(
		&v.ID, &v.Identifier, &v.Token, &verType, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("verification not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	v.Type = verification.VerificationType(verType)
	return &v, nil
}

func (r *txVerificationRepository) FindByIdentifierAndType(identifier string, verType verification.VerificationType) (*verification.Verification, error) {
	query := `
		SELECT id, identifier, token, type, expires_at, created_at, updated_at
		FROM verifications
		WHERE identifier = $1 AND type = $2
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var v verification.Verification
	var typeStr string
	err := r.tx.QueryRow(query, identifier, string(verType)).Scan(
		&v.ID, &v.Identifier, &v.Token, &typeStr, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("verification not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	v.Type = verification.VerificationType(typeStr)
	return &v, nil
}

func (r *txVerificationRepository) Delete(id string) error {
	query := `DELETE FROM verifications WHERE id = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.tx.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete verification: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

func (r *txVerificationRepository) DeleteByToken(token string) error {
	query := `DELETE FROM verifications WHERE token = $1`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.tx.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to delete verification: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

func (r *txVerificationRepository) DeleteExpired() error {
	query := `DELETE FROM verifications WHERE expires_at < NOW()`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.tx.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to delete expired verifications: %w", err)
	}

	return nil
}

func (r *txVerificationRepository) Count() (int, error) {
	query := `SELECT COUNT(*) FROM verifications`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.tx.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count verifications: %w", err)
	}

	return count, nil
}

func (r *txVerificationRepository) ExistsByToken(token string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM verifications WHERE token = $1)`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var exists bool
	err := r.tx.QueryRow(query, token).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check verification existence: %w", err)
	}

	return exists, nil
}

func (r *txVerificationRepository) ExistsByIdentifierAndType(identifier string, verType verification.VerificationType) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM verifications WHERE identifier = $1 AND type = $2)`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var exists bool
	err := r.tx.QueryRow(query, identifier, string(verType)).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check verification existence: %w", err)
	}

	return exists, nil
}
