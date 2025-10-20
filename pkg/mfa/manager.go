package mfa

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPManager handles TOTP generation, verification, and QR code generation
type TOTPManager struct {
	Issuer string
}

// NewTOTPManager creates a new TOTP manager
func NewTOTPManager(issuer string) *TOTPManager {
	return &TOTPManager{
		Issuer: issuer,
	}
}

// GenerateSecret generates a new TOTP secret
func (tm *TOTPManager) GenerateSecret(email string) (*TOTPSecret, error) {
	// Generate a new secret key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      tm.Issuer,
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}

	// Generate QR code
	qrCode := key.URL()

	return &TOTPSecret{
		Secret: key.Secret(),
		QRCode: qrCode,
	}, nil
}

// VerifyCode verifies a TOTP code
func (tm *TOTPManager) VerifyCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// VerifyCodeWithTime verifies a TOTP code with a specific time
func (tm *TOTPManager) VerifyCodeWithTime(secret, code string, t time.Time) bool {
	valid, err := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return valid
}

// GenerateBackupCodes generates a list of backup codes
func (tm *TOTPManager) GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := tm.generateRandomCode(8)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

// generateRandomCode generates a random alphanumeric code
func (tm *TOTPManager) generateRandomCode(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(bytes)[:length], nil
}

// TOTPSecret represents a TOTP secret response
type TOTPSecret struct {
	Secret string // Base32 encoded secret
	QRCode string // QR code URL
}

// GetCurrentCode returns the current TOTP code (for testing purposes)
func (tm *TOTPManager) GetCurrentCode(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", err
	}
	return code, nil
}

// GenerateProvisioningURI generates a provisioning URI for the secret
func (tm *TOTPManager) GenerateProvisioningURI(email, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", tm.Issuer, email, secret, tm.Issuer)
}
