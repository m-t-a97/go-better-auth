package domain

import (
	"context"
	"time"
)

// TwoFactorAuthMethod represents the method of two-factor authentication
type TwoFactorAuthMethod string

const (
	TOTP TwoFactorAuthMethod = "totp"
	SMS  TwoFactorAuthMethod = "sms"
)

// TwoFactorAuth represents a user's two-factor authentication configuration
type TwoFactorAuth struct {
	ID          string
	UserID      string
	Method      TwoFactorAuthMethod
	IsEnabled   bool
	BackupCodes []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	VerifiedAt  *time.Time
	DisabledAt  *time.Time
}

// TOTPSecret represents TOTP-specific configuration
type TOTPSecret struct {
	ID                string
	UserID            string
	Secret            string // Base32 encoded secret
	QRCode            string // QR code URL for authenticator app
	BackupCodes       []string
	IsVerified        bool
	VerificationCount int
	CreatedAt         time.Time
	UpdatedAt         time.Time
	VerifiedAt        *time.Time
}

// MFAChallenge represents a pending MFA challenge (e.g., for TOTP verification during login)
type MFAChallenge struct {
	ID        string
	UserID    string
	Method    TwoFactorAuthMethod
	Challenge string // Challenge token or session ID
	ExpiresAt time.Time
	CreatedAt time.Time
}

// TwoFactorAuthRepository defines the interface for MFA data operations
type TwoFactorAuthRepository interface {
	Create(ctx context.Context, mfa *TwoFactorAuth) error
	FindByUserID(ctx context.Context, userID string) (*TwoFactorAuth, error)
	FindByUserIDAndMethod(ctx context.Context, userID string, method TwoFactorAuthMethod) (*TwoFactorAuth, error)
	Update(ctx context.Context, mfa *TwoFactorAuth) error
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}

// TOTPSecretRepository defines the interface for TOTP secret storage
type TOTPSecretRepository interface {
	Create(ctx context.Context, secret *TOTPSecret) error
	FindByUserID(ctx context.Context, userID string) (*TOTPSecret, error)
	Update(ctx context.Context, secret *TOTPSecret) error
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}

// MFAChallengeRepository defines the interface for MFA challenge storage
type MFAChallengeRepository interface {
	Create(ctx context.Context, challenge *MFAChallenge) error
	FindByID(ctx context.Context, id string) (*MFAChallenge, error)
	FindByUserIDAndMethod(ctx context.Context, userID string, method TwoFactorAuthMethod) (*MFAChallenge, error)
	Update(ctx context.Context, challenge *MFAChallenge) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}
