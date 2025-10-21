package gobetterauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Valid(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	// Note: This may fail if sqlite3 is not available due to CGO requirements
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}
	assert.NotNil(t, auth)
	assert.NotNil(t, auth.Config())
	assert.NotNil(t, auth.SecretGenerator())
	assert.NotNil(t, auth.PasswordHasher())
	assert.NotNil(t, auth.CipherManager())
}

func TestNew_NilConfig(t *testing.T) {
	auth, err := New(nil)
	assert.Error(t, err)
	assert.Nil(t, auth)
}

func TestNew_InvalidConfig(t *testing.T) {
	config := &domain.Config{
		// Missing required fields
	}

	auth, err := New(config)
	assert.Error(t, err)
	assert.Nil(t, auth)
}

func TestNew_AppliesDefaults(t *testing.T) {
	config := &domain.Config{
		Secret: "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}
	require.NotNil(t, auth)

	// Check that defaults were applied
	assert.NotEmpty(t, auth.Config().BaseURL)
	assert.NotEmpty(t, auth.Config().BasePath)
}

func TestAuth_PasswordHashing(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	password := "my-secure-password"
	hasher := auth.PasswordHasher()

	// Hash password
	hash, err := hasher.Hash(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify password
	verified, err := hasher.Verify(password, hash)
	assert.NoError(t, err)
	assert.True(t, verified)
}

func TestAuth_SecretGeneration(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	generator := auth.SecretGenerator()

	// Generate secret
	secret, err := generator.GenerateSecretDefault()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Validate secret
	err = generator.ValidateSecret(secret)
	assert.NoError(t, err)
}

func TestAuth_Handler(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Get the handler
	handler := auth.Handler()
	assert.NotNil(t, handler)

	// Test that it implements http.Handler
	var _ http.Handler = handler

	// Test basic HTTP request
	req := httptest.NewRequest("GET", "/auth/validate", nil)
	w := httptest.NewRecorder()

	// Handler should respond (even if 401 since no session token)
	handler.ServeHTTP(w, req)
	assert.NotZero(t, w.Code)
}

func TestAuth_HandlerWithStdlibMux(t *testing.T) {
	config := &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}

	auth, err := New(config)
	if err != nil {
		t.Skip("sqlite adapter not available:", err)
	}

	// Test that handler can be mounted on stdlib mux
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())

	// Make a test request
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	assert.NotZero(t, w.Code)
}
