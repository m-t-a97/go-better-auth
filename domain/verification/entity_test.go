package verification

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateCreateVerificationRequest_Valid(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "user@example.com",
		Token:      "verification-token-123456",
		Type:       TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.NoError(t, err)
}

func TestValidateCreateVerificationRequest_ValidPasswordReset(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "user-123",
		Token:      "reset-token-123456",
		Type:       TypePasswordReset,
		ExpiresAt:  time.Now().Add(30 * time.Minute),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.NoError(t, err)
}

func TestValidateCreateVerificationRequest_Nil(t *testing.T) {
	err := ValidateCreateVerificationRequest(nil)
	assert.Error(t, err)
}

func TestValidateCreateVerificationRequest_EmptyIdentifier(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "",
		Token:      "verification-token-123456",
		Type:       TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateVerificationRequest_IdentifierTooLong(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: string(make([]byte, 300)),
		Token:      "verification-token-123456",
		Type:       TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateVerificationRequest_EmptyToken(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "user@example.com",
		Token:      "",
		Type:       TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateVerificationRequest_TokenTooLong(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "user@example.com",
		Token:      string(make([]byte, 600)),
		Type:       TypeEmailVerification,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateVerificationRequest_EmptyType(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "user@example.com",
		Token:      "verification-token-123456",
		Type:       "",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateVerificationRequest_InvalidType(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "user@example.com",
		Token:      "verification-token-123456",
		Type:       "invalid_type",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateVerificationRequest_NoExpirationTime(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "user@example.com",
		Token:      "verification-token-123456",
		Type:       TypeEmailVerification,
	}

	err := ValidateCreateVerificationRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateVerificationRequest_ExpirationInPast(t *testing.T) {
	req := &CreateVerificationRequest{
		Identifier: "user@example.com",
		Token:      "verification-token-123456",
		Type:       TypeEmailVerification,
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}

	err := ValidateCreateVerificationRequest(req)
	assert.Error(t, err)
}

func TestVerification_IsExpired_False(t *testing.T) {
	verification := &Verification{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	assert.False(t, verification.IsExpired())
}

func TestVerification_IsExpired_True(t *testing.T) {
	verification := &Verification{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	assert.True(t, verification.IsExpired())
}

func TestIsValidType_Valid(t *testing.T) {
	validTypes := []VerificationType{
		TypeEmailVerification,
		TypePasswordReset,
		TypeEmailChange,
	}

	for _, vType := range validTypes {
		assert.True(t, isValidType(vType))
	}
}

func TestIsValidType_Invalid(t *testing.T) {
	assert.False(t, isValidType("invalid"))
	assert.False(t, isValidType("sms_verification"))
}
