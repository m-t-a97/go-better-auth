package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/m-t-a97/go-better-auth/internal/domain"
)

// TwoFactorAuthAdapter implements the TwoFactorAuthRepository for PostgreSQL
type TwoFactorAuthAdapter struct {
	db *sql.DB
}

// NewTwoFactorAuthAdapter creates a new PostgreSQL adapter for TwoFactorAuthRepository
func NewTwoFactorAuthAdapter(db *sql.DB) *TwoFactorAuthAdapter {
	return &TwoFactorAuthAdapter{db: db}
}

// Create inserts a new two-factor auth record
func (a *TwoFactorAuthAdapter) Create(ctx context.Context, mfa *domain.TwoFactorAuth) error {
	backupCodesJSON, err := json.Marshal(mfa.BackupCodes)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO two_factor_auth (id, user_id, method, is_enabled, backup_codes, created_at, updated_at, verified_at, disabled_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	mfa.ID = uuid.New().String()
	now := time.Now().UTC()
	mfa.CreatedAt = now
	mfa.UpdatedAt = now

	_, err = a.db.ExecContext(ctx, query,
		mfa.ID,
		mfa.UserID,
		string(mfa.Method),
		mfa.IsEnabled,
		backupCodesJSON,
		mfa.CreatedAt,
		mfa.UpdatedAt,
		mfa.VerifiedAt,
		mfa.DisabledAt,
	)

	return err
}

// FindByUserID finds a two-factor auth record by user ID
func (a *TwoFactorAuthAdapter) FindByUserID(ctx context.Context, userID string) (*domain.TwoFactorAuth, error) {
	query := `
		SELECT id, user_id, method, is_enabled, backup_codes, created_at, updated_at, verified_at, disabled_at
		FROM two_factor_auth
		WHERE user_id = $1
		LIMIT 1
	`

	mfa := &domain.TwoFactorAuth{}
	backupCodesJSON := []byte{}

	err := a.db.QueryRowContext(ctx, query, userID).Scan(
		&mfa.ID,
		&mfa.UserID,
		(*string)(&mfa.Method),
		&mfa.IsEnabled,
		&backupCodesJSON,
		&mfa.CreatedAt,
		&mfa.UpdatedAt,
		&mfa.VerifiedAt,
		&mfa.DisabledAt,
	)

	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(backupCodesJSON, &mfa.BackupCodes)
	if err != nil {
		return nil, err
	}

	return mfa, nil
}

// FindByUserIDAndMethod finds a two-factor auth record by user ID and method
func (a *TwoFactorAuthAdapter) FindByUserIDAndMethod(ctx context.Context, userID string, method domain.TwoFactorAuthMethod) (*domain.TwoFactorAuth, error) {
	query := `
		SELECT id, user_id, method, is_enabled, backup_codes, created_at, updated_at, verified_at, disabled_at
		FROM two_factor_auth
		WHERE user_id = $1 AND method = $2
		LIMIT 1
	`

	mfa := &domain.TwoFactorAuth{}
	backupCodesJSON := []byte{}

	err := a.db.QueryRowContext(ctx, query, userID, string(method)).Scan(
		&mfa.ID,
		&mfa.UserID,
		(*string)(&mfa.Method),
		&mfa.IsEnabled,
		&backupCodesJSON,
		&mfa.CreatedAt,
		&mfa.UpdatedAt,
		&mfa.VerifiedAt,
		&mfa.DisabledAt,
	)

	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(backupCodesJSON, &mfa.BackupCodes)
	if err != nil {
		return nil, err
	}

	return mfa, nil
}

// Update updates an existing two-factor auth record
func (a *TwoFactorAuthAdapter) Update(ctx context.Context, mfa *domain.TwoFactorAuth) error {
	backupCodesJSON, err := json.Marshal(mfa.BackupCodes)
	if err != nil {
		return err
	}

	mfa.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE two_factor_auth
		SET method = $1, is_enabled = $2, backup_codes = $3, updated_at = $4, verified_at = $5, disabled_at = $6
		WHERE id = $7
	`

	result, err := a.db.ExecContext(ctx, query,
		string(mfa.Method),
		mfa.IsEnabled,
		backupCodesJSON,
		mfa.UpdatedAt,
		mfa.VerifiedAt,
		mfa.DisabledAt,
		mfa.ID,
	)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// Delete deletes a two-factor auth record
func (a *TwoFactorAuthAdapter) Delete(ctx context.Context, id string) error {
	query := "DELETE FROM two_factor_auth WHERE id = $1"
	result, err := a.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// DeleteByUserID deletes all two-factor auth records for a user
func (a *TwoFactorAuthAdapter) DeleteByUserID(ctx context.Context, userID string) error {
	query := "DELETE FROM two_factor_auth WHERE user_id = $1"
	_, err := a.db.ExecContext(ctx, query, userID)
	return err
}

// TOTPSecretAdapter implements the TOTPSecretRepository for PostgreSQL
type TOTPSecretAdapter struct {
	db *sql.DB
}

// NewTOTPSecretAdapter creates a new PostgreSQL adapter for TOTPSecretRepository
func NewTOTPSecretAdapter(db *sql.DB) *TOTPSecretAdapter {
	return &TOTPSecretAdapter{db: db}
}

// Create inserts a new TOTP secret
func (a *TOTPSecretAdapter) Create(ctx context.Context, secret *domain.TOTPSecret) error {
	backupCodesJSON, err := json.Marshal(secret.BackupCodes)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO totp_secrets (id, user_id, secret, qr_code, backup_codes, is_verified, verification_count, created_at, updated_at, verified_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	secret.ID = uuid.New().String()
	now := time.Now().UTC()
	secret.CreatedAt = now
	secret.UpdatedAt = now

	_, err = a.db.ExecContext(ctx, query,
		secret.ID,
		secret.UserID,
		secret.Secret,
		secret.QRCode,
		backupCodesJSON,
		secret.IsVerified,
		secret.VerificationCount,
		secret.CreatedAt,
		secret.UpdatedAt,
		secret.VerifiedAt,
	)

	return err
}

// FindByUserID finds a TOTP secret by user ID
func (a *TOTPSecretAdapter) FindByUserID(ctx context.Context, userID string) (*domain.TOTPSecret, error) {
	query := `
		SELECT id, user_id, secret, qr_code, backup_codes, is_verified, verification_count, created_at, updated_at, verified_at
		FROM totp_secrets
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	secret := &domain.TOTPSecret{}
	backupCodesJSON := []byte{}

	err := a.db.QueryRowContext(ctx, query, userID).Scan(
		&secret.ID,
		&secret.UserID,
		&secret.Secret,
		&secret.QRCode,
		&backupCodesJSON,
		&secret.IsVerified,
		&secret.VerificationCount,
		&secret.CreatedAt,
		&secret.UpdatedAt,
		&secret.VerifiedAt,
	)

	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(backupCodesJSON, &secret.BackupCodes)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// Update updates an existing TOTP secret
func (a *TOTPSecretAdapter) Update(ctx context.Context, secret *domain.TOTPSecret) error {
	backupCodesJSON, err := json.Marshal(secret.BackupCodes)
	if err != nil {
		return err
	}

	secret.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE totp_secrets
		SET secret = $1, qr_code = $2, backup_codes = $3, is_verified = $4, verification_count = $5, updated_at = $6, verified_at = $7
		WHERE id = $8
	`

	result, err := a.db.ExecContext(ctx, query,
		secret.Secret,
		secret.QRCode,
		backupCodesJSON,
		secret.IsVerified,
		secret.VerificationCount,
		secret.UpdatedAt,
		secret.VerifiedAt,
		secret.ID,
	)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// Delete deletes a TOTP secret
func (a *TOTPSecretAdapter) Delete(ctx context.Context, id string) error {
	query := "DELETE FROM totp_secrets WHERE id = $1"
	result, err := a.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// DeleteByUserID deletes all TOTP secrets for a user
func (a *TOTPSecretAdapter) DeleteByUserID(ctx context.Context, userID string) error {
	query := "DELETE FROM totp_secrets WHERE user_id = $1"
	_, err := a.db.ExecContext(ctx, query, userID)
	return err
}

// MFAChallengeAdapter implements the MFAChallengeRepository for PostgreSQL
type MFAChallengeAdapter struct {
	db *sql.DB
}

// NewMFAChallengeAdapter creates a new PostgreSQL adapter for MFAChallengeRepository
func NewMFAChallengeAdapter(db *sql.DB) *MFAChallengeAdapter {
	return &MFAChallengeAdapter{db: db}
}

// Create inserts a new MFA challenge
func (a *MFAChallengeAdapter) Create(ctx context.Context, challenge *domain.MFAChallenge) error {
	query := `
		INSERT INTO mfa_challenges (id, user_id, method, challenge, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	challenge.ID = uuid.New().String()
	challenge.CreatedAt = time.Now().UTC()

	_, err := a.db.ExecContext(ctx, query,
		challenge.ID,
		challenge.UserID,
		string(challenge.Method),
		challenge.Challenge,
		challenge.ExpiresAt,
		challenge.CreatedAt,
	)

	return err
}

// FindByID finds an MFA challenge by ID
func (a *MFAChallengeAdapter) FindByID(ctx context.Context, id string) (*domain.MFAChallenge, error) {
	query := `
		SELECT id, user_id, method, challenge, expires_at, created_at
		FROM mfa_challenges
		WHERE id = $1 AND expires_at > NOW()
	`

	challenge := &domain.MFAChallenge{}
	method := ""

	err := a.db.QueryRowContext(ctx, query, id).Scan(
		&challenge.ID,
		&challenge.UserID,
		&method,
		&challenge.Challenge,
		&challenge.ExpiresAt,
		&challenge.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	challenge.Method = domain.TwoFactorAuthMethod(method)
	return challenge, nil
}

// FindByUserIDAndMethod finds an MFA challenge by user ID and method
func (a *MFAChallengeAdapter) FindByUserIDAndMethod(ctx context.Context, userID string, method domain.TwoFactorAuthMethod) (*domain.MFAChallenge, error) {
	query := `
		SELECT id, user_id, method, challenge, expires_at, created_at
		FROM mfa_challenges
		WHERE user_id = $1 AND method = $2 AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1
	`

	challenge := &domain.MFAChallenge{}
	methodStr := ""

	err := a.db.QueryRowContext(ctx, query, userID, string(method)).Scan(
		&challenge.ID,
		&challenge.UserID,
		&methodStr,
		&challenge.Challenge,
		&challenge.ExpiresAt,
		&challenge.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	challenge.Method = domain.TwoFactorAuthMethod(methodStr)
	return challenge, nil
}

// Update updates an existing MFA challenge
func (a *MFAChallengeAdapter) Update(ctx context.Context, challenge *domain.MFAChallenge) error {
	query := `
		UPDATE mfa_challenges
		SET challenge = $1, expires_at = $2
		WHERE id = $3
	`

	result, err := a.db.ExecContext(ctx, query, challenge.Challenge, challenge.ExpiresAt, challenge.ID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// Delete deletes an MFA challenge
func (a *MFAChallengeAdapter) Delete(ctx context.Context, id string) error {
	query := "DELETE FROM mfa_challenges WHERE id = $1"
	result, err := a.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// DeleteExpired deletes expired MFA challenges
func (a *MFAChallengeAdapter) DeleteExpired(ctx context.Context) error {
	query := "DELETE FROM mfa_challenges WHERE expires_at <= NOW()"
	_, err := a.db.ExecContext(ctx, query)
	return err
}
