package domain

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateConfig_Valid(t *testing.T) {
	config := &Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	result := ValidateConfig(config)
	assert.True(t, result.Valid, "config should be valid")
	assert.Empty(t, result.Errors, "should have no validation errors")
}

func TestValidateConfig_MissingBaseURL(t *testing.T) {
	config := &Config{
		Secret: "very-secret-key-that-is-long-enough",
		Database: DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	result := ValidateConfig(config)
	assert.False(t, result.Valid, "config should be invalid")
	assert.NotEmpty(t, result.Errors, "should have validation errors")
}

func TestValidateConfig_InvalidBaseURL(t *testing.T) {
	config := &Config{
		BaseURL: "not a valid url",
		Secret:  "very-secret-key-that-is-long-enough",
	}

	result := ValidateConfig(config)
	assert.False(t, result.Valid, "config should be invalid")
}

func TestValidateConfig_ShortSecret(t *testing.T) {
	config := &Config{
		BaseURL: "http://localhost:8080",
		Secret:  "short",
		Database: DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	result := ValidateConfig(config)
	assert.False(t, result.Valid, "config should be invalid")
}

func TestValidateConfig_MissingSecret(t *testing.T) {
	config := &Config{
		BaseURL: "http://localhost:8080",
		Database: DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	result := ValidateConfig(config)
	assert.False(t, result.Valid, "config should be invalid")
}

func TestValidateDatabaseConfig_ValidSQLite(t *testing.T) {
	config := &DatabaseConfig{
		Provider:         "sqlite",
		ConnectionString: ":memory:",
	}

	err := validateDatabaseConfig(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateDatabaseConfig_ValidPostgres(t *testing.T) {
	config := &DatabaseConfig{
		Provider:         "postgres",
		ConnectionString: "postgres://user:pass@localhost/db",
	}

	err := validateDatabaseConfig(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateDatabaseConfig_InvalidProvider(t *testing.T) {
	config := &DatabaseConfig{
		Provider:         "mysql",
		ConnectionString: "mysql://localhost",
	}

	err := validateDatabaseConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateDatabaseConfig_MissingConnectionString(t *testing.T) {
	config := &DatabaseConfig{
		Provider: "sqlite",
	}

	err := validateDatabaseConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateTrustedOrigins_Valid(t *testing.T) {
	config := &TrustedOriginsConfig{
		StaticOrigins: []string{
			"http://localhost:3000",
			"https://example.com",
			"https://*.example.com",
		},
	}

	err := validateTrustedOrigins(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateTrustedOrigins_InvalidURL(t *testing.T) {
	config := &TrustedOriginsConfig{
		StaticOrigins: []string{
			"ht!tp://not a valid url",
		},
	}

	err := validateTrustedOrigins(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateEmailPasswordConfig_Valid(t *testing.T) {
	config := &EmailPasswordConfig{
		Enabled:                     true,
		MinPasswordLength:           8,
		MaxPasswordLength:           128,
		ResetPasswordTokenExpiresIn: 3600,
	}

	err := validateEmailPasswordConfig(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateEmailPasswordConfig_MinTooShort(t *testing.T) {
	config := &EmailPasswordConfig{
		Enabled:           true,
		MinPasswordLength: 2,
		MaxPasswordLength: 128,
	}

	err := validateEmailPasswordConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateEmailPasswordConfig_MaxLessThanMin(t *testing.T) {
	config := &EmailPasswordConfig{
		Enabled:           true,
		MinPasswordLength: 100,
		MaxPasswordLength: 50,
	}

	err := validateEmailPasswordConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateSessionConfig_Valid(t *testing.T) {
	config := &SessionConfig{
		ExpiresIn: 604800,
		UpdateAge: 86400,
	}

	err := validateSessionConfig(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateSessionConfig_InvalidExpiresIn(t *testing.T) {
	config := &SessionConfig{
		ExpiresIn: 100, // Too small
		UpdateAge: 50,
	}

	err := validateSessionConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateSessionConfig_UpdateAgeGreaterThanExpiresIn(t *testing.T) {
	config := &SessionConfig{
		ExpiresIn: 3600,
		UpdateAge: 7200, // Greater than ExpiresIn
	}

	err := validateSessionConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateRateLimitConfig_Valid(t *testing.T) {
	config := &RateLimitOptions{
		Enabled: true,
		Window:  10,
		Max:     100,
		Storage: "memory",
	}

	err := validateRateLimitConfig(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateRateLimitConfig_InvalidStorage(t *testing.T) {
	config := &RateLimitOptions{
		Enabled: true,
		Window:  10,
		Max:     100,
		Storage: "invalid",
	}

	err := validateRateLimitConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateRateLimitConfig_CustomRulesValid(t *testing.T) {
	config := &RateLimitOptions{
		Enabled: true,
		Window:  10,
		Max:     100,
		CustomRules: map[string]RateLimitRule{
			"/api/auth/sign-in": {
				Window: 5,
				Max:    5,
			},
		},
	}

	err := validateRateLimitConfig(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateRateLimitConfig_CustomRulesInvalid(t *testing.T) {
	config := &RateLimitOptions{
		Enabled: true,
		Window:  10,
		Max:     100,
		CustomRules: map[string]RateLimitRule{
			"/api/auth/sign-in": {
				Window: 5,
				Max:    0, // Invalid
			},
		},
	}

	err := validateRateLimitConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateAdvancedConfig_ValidCookiePrefix(t *testing.T) {
	config := &AdvancedConfig{
		CookiePrefix: "auth_",
	}

	err := validateAdvancedConfig(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateAdvancedConfig_CookiePrefixTooLong(t *testing.T) {
	config := &AdvancedConfig{
		CookiePrefix: "x" + string(make([]byte, 50)),
	}

	err := validateAdvancedConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateAdvancedConfig_CookiePrefixWithSpaces(t *testing.T) {
	config := &AdvancedConfig{
		CookiePrefix: "auth prefix",
	}

	err := validateAdvancedConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateLoggerConfig_ValidLevels(t *testing.T) {
	levels := []LogLevel{LogLevelInfo, LogLevelWarn, LogLevelError, LogLevelDebug}

	for _, level := range levels {
		config := &LoggerConfig{
			Level: level,
		}
		err := validateLoggerConfig(config)
		assert.NoError(t, err, "level %s should be valid", level)
	}
}

func TestValidateLoggerConfig_InvalidLevel(t *testing.T) {
	config := &LoggerConfig{
		Level: "invalid",
	}

	err := validateLoggerConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestConfigValidationResult_Error(t *testing.T) {
	result := &ConfigValidationResult{
		Valid: false,
		Errors: []ValidationError{
			{Field: "BaseURL", Message: "is required"},
			{Field: "Secret", Message: "is too short"},
		},
	}

	errorMsg := result.Error()
	assert.Contains(t, errorMsg, "BaseURL")
	assert.Contains(t, errorMsg, "Secret")
	assert.Contains(t, errorMsg, "Configuration validation failed")
}

func TestConfigValidationResult_Error_Valid(t *testing.T) {
	result := &ConfigValidationResult{
		Valid:  true,
		Errors: []ValidationError{},
	}

	errorMsg := result.Error()
	assert.Empty(t, errorMsg)
}

func TestValidateEmailVerificationConfig_Valid(t *testing.T) {
	config := &EmailVerificationConfig{
		ExpiresIn: 3600,
	}

	err := validateEmailVerificationConfig(config)
	assert.NoError(t, err, "should be valid")
}

func TestValidateEmailVerificationConfig_TooSmall(t *testing.T) {
	config := &EmailVerificationConfig{
		ExpiresIn: 30, // Less than 60
	}

	err := validateEmailVerificationConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateCrosSubDomainCookies_MissingDomain(t *testing.T) {
	config := &AdvancedConfig{
		CrossSubDomainCookies: &CrossSubDomainCookiesConfig{
			Enabled: true,
		},
	}

	err := validateAdvancedConfig(config)
	assert.Error(t, err, "should be invalid")
}

func TestValidateCrosSubDomainCookies_Valid(t *testing.T) {
	config := &AdvancedConfig{
		CrossSubDomainCookies: &CrossSubDomainCookiesConfig{
			Enabled: true,
			Domain:  ".example.com",
		},
	}

	err := validateAdvancedConfig(config)
	assert.NoError(t, err, "should be valid")
}

// Tests for TrustedOriginsConfig.IsOriginTrusted

func TestTrustedOriginsConfig_IsOriginTrusted_Static(t *testing.T) {
	config := &TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com", "https://app.example.com"},
	}

	tests := []struct {
		name     string
		origin   string
		expected bool
	}{
		{"exact match first", "https://example.com", true},
		{"exact match second", "https://app.example.com", true},
		{"no match", "https://other.com", false},
		{"empty origin", "", false},
		{"case sensitive", "https://Example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.IsOriginTrusted(tt.origin, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTrustedOriginsConfig_IsOriginTrusted_Dynamic(t *testing.T) {
	req := &http.Request{}

	config := &TrustedOriginsConfig{
		StaticOrigins: []string{},
		DynamicOrigins: func(r *http.Request) []string {
			return []string{"https://dynamic.example.com"}
		},
	}

	tests := []struct {
		name     string
		origin   string
		expected bool
	}{
		{"dynamic match", "https://dynamic.example.com", true},
		{"dynamic no match", "https://other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.IsOriginTrusted(tt.origin, req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTrustedOriginsConfig_IsOriginTrusted_Wildcard(t *testing.T) {
	config := &TrustedOriginsConfig{
		StaticOrigins: []string{
			"https://*.example.com",
			"https://app.com",
		},
	}

	tests := []struct {
		name     string
		origin   string
		expected bool
	}{
		{"wildcard subdomain match", "https://api.example.com", true},
		{"wildcard subdomain another", "https://app-v2.example.com", true},
		{"exact match", "https://app.com", true},
		{"no match", "https://other.com", false},
		{"wrong domain for wildcard", "https://api.example.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.IsOriginTrusted(tt.origin, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTrustedOriginsConfig_IsOriginTrusted_Nil(t *testing.T) {
	var config *TrustedOriginsConfig
	result := config.IsOriginTrusted("https://example.com", nil)
	assert.False(t, result)
}

func TestMatchesOriginPattern(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		pattern  string
		expected bool
	}{
		{"exact match", "https://example.com", "https://example.com", true},
		{"wildcard subdomain", "https://api.example.com", "https://*.example.com", true},
		{"wildcard full", "https://anything.com", "https://*", true},
		{"no match", "https://example.com", "https://other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesOriginPattern(tt.origin, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}
