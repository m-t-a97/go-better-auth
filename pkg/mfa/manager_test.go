package mfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOTPManager_GenerateSecret(t *testing.T) {
	manager := NewTOTPManager("TestIssuer")
	email := "user@example.com"

	secret, err := manager.GenerateSecret(email)
	require.NoError(t, err)
	assert.NotEmpty(t, secret.Secret)
	assert.NotEmpty(t, secret.QRCode)
	assert.Contains(t, secret.QRCode, "otpauth://totp/")
	assert.Contains(t, secret.QRCode, email)
}

func TestTOTPManager_VerifyCode(t *testing.T) {
	manager := NewTOTPManager("TestIssuer")
	email := "user@example.com"

	// Generate a secret
	secret, err := manager.GenerateSecret(email)
	require.NoError(t, err)

	// Get current code
	currentCode, err := manager.GetCurrentCode(secret.Secret)
	require.NoError(t, err)
	assert.Len(t, currentCode, 6)

	// Verify the current code
	isValid := manager.VerifyCode(secret.Secret, currentCode)
	assert.True(t, isValid)

	// Verify an invalid code
	isValid = manager.VerifyCode(secret.Secret, "000000")
	assert.False(t, isValid)
}

func TestTOTPManager_VerifyCodeWithTime(t *testing.T) {
	manager := NewTOTPManager("TestIssuer")
	email := "user@example.com"

	// Generate a secret
	secret, err := manager.GenerateSecret(email)
	require.NoError(t, err)

	// Get current code
	now := time.Now()
	currentCode, err := manager.GetCurrentCode(secret.Secret)
	require.NoError(t, err)

	// Verify the code with the current time
	isValid := manager.VerifyCodeWithTime(secret.Secret, currentCode, now)
	assert.True(t, isValid)

	// Verify the code with a time in the past (within skew window)
	isValid = manager.VerifyCodeWithTime(secret.Secret, currentCode, now.Add(-30*time.Second))
	assert.True(t, isValid)

	// Verify an invalid code
	isValid = manager.VerifyCodeWithTime(secret.Secret, "000000", now)
	assert.False(t, isValid)
}

func TestTOTPManager_GenerateBackupCodes(t *testing.T) {
	manager := NewTOTPManager("TestIssuer")

	codes, err := manager.GenerateBackupCodes(10)
	require.NoError(t, err)
	assert.Len(t, codes, 10)

	// Check that all codes are unique
	uniqueCodes := make(map[string]bool)
	for _, code := range codes {
		assert.NotEmpty(t, code)
		uniqueCodes[code] = true
	}
	assert.Len(t, uniqueCodes, 10)
}

func TestTOTPManager_GenerateProvisioningURI(t *testing.T) {
	manager := NewTOTPManager("MyApp")
	email := "user@example.com"
	secret := "JBSWY3DPEBLW64TMMQ======"

	uri := manager.GenerateProvisioningURI(email, secret)
	assert.Contains(t, uri, "otpauth://totp/")
	assert.Contains(t, uri, email)
	assert.Contains(t, uri, secret)
	assert.Contains(t, uri, "issuer=MyApp")
}

func TestTOTPManager_GetCurrentCode(t *testing.T) {
	manager := NewTOTPManager("TestIssuer")
	email := "user@example.com"

	// Generate a secret
	secret, err := manager.GenerateSecret(email)
	require.NoError(t, err)

	// Get current code multiple times
	code1, err := manager.GetCurrentCode(secret.Secret)
	require.NoError(t, err)
	assert.Len(t, code1, 6)

	// Codes should be numeric
	for _, ch := range code1 {
		assert.True(t, ch >= '0' && ch <= '9')
	}
}
