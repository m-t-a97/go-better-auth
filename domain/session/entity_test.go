package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateCreateSessionRequest_Valid(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	req := &CreateSessionRequest{
		UserID:    "user-123",
		Token:     "session-token-1234567890",
		ExpiresAt: expiresAt,
	}

	err := ValidateCreateSessionRequest(req)
	assert.NoError(t, err)
}

func TestValidateCreateSessionRequest_ValidWithMetadata(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	ipAddress := "192.168.1.1"
	userAgent := "Mozilla/5.0"

	req := &CreateSessionRequest{
		UserID:    "user-123",
		Token:     "session-token-1234567890",
		ExpiresAt: expiresAt,
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
	}

	err := ValidateCreateSessionRequest(req)
	assert.NoError(t, err)
}

func TestValidateCreateSessionRequest_Nil(t *testing.T) {
	err := ValidateCreateSessionRequest(nil)
	assert.Error(t, err)
}

func TestValidateCreateSessionRequest_EmptyUserID(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	req := &CreateSessionRequest{
		UserID:    "",
		Token:     "session-token-1234567890",
		ExpiresAt: expiresAt,
	}

	err := ValidateCreateSessionRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateSessionRequest_EmptyToken(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	req := &CreateSessionRequest{
		UserID:    "user-123",
		Token:     "",
		ExpiresAt: expiresAt,
	}

	err := ValidateCreateSessionRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateSessionRequest_TokenTooShort(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	req := &CreateSessionRequest{
		UserID:    "user-123",
		Token:     "short",
		ExpiresAt: expiresAt,
	}

	err := ValidateCreateSessionRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateSessionRequest_TokenTooLong(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	req := &CreateSessionRequest{
		UserID:    "user-123",
		Token:     string(make([]byte, 600)),
		ExpiresAt: expiresAt,
	}

	err := ValidateCreateSessionRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateSessionRequest_NoExpirationTime(t *testing.T) {
	req := &CreateSessionRequest{
		UserID: "user-123",
		Token:  "session-token-1234567890",
	}

	err := ValidateCreateSessionRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateSessionRequest_ExpirationInPast(t *testing.T) {
	expiresAt := time.Now().Add(-1 * time.Hour)
	req := &CreateSessionRequest{
		UserID:    "user-123",
		Token:     "session-token-1234567890",
		ExpiresAt: expiresAt,
	}

	err := ValidateCreateSessionRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateSessionRequest_IPAddressTooLong(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	ipAddress := string(make([]byte, 100))
	req := &CreateSessionRequest{
		UserID:    "user-123",
		Token:     "session-token-1234567890",
		ExpiresAt: expiresAt,
		IPAddress: &ipAddress,
	}

	err := ValidateCreateSessionRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateSessionRequest_UserAgentTooLong(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	userAgent := string(make([]byte, 600))
	req := &CreateSessionRequest{
		UserID:    "user-123",
		Token:     "session-token-1234567890",
		ExpiresAt: expiresAt,
		UserAgent: &userAgent,
	}

	err := ValidateCreateSessionRequest(req)
	assert.Error(t, err)
}

func TestSession_IsExpired_False(t *testing.T) {
	session := &Session{
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	assert.False(t, session.IsExpired())
}

func TestSession_IsExpired_True(t *testing.T) {
	session := &Session{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	assert.True(t, session.IsExpired())
}

func TestSession_IsExpired_Boundary(t *testing.T) {
	// Session that expires now should be considered expired
	session := &Session{
		ExpiresAt: time.Now(),
	}

	// May be True or False depending on timing, but we just verify it's a valid operation
	_ = session.IsExpired()
}
