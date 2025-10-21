package gobetterauth

import (
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
	assert.NoError(t, err)
	assert.NotNil(t, auth)
	assert.NotNil(t, auth.Config())
	assert.NotNil(t, auth.SecretGenerator())
	assert.NotNil(t, auth.PasswordHasher())
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
	require.NoError(t, err)
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
	require.NoError(t, err)

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
	require.NoError(t, err)

	generator := auth.SecretGenerator()

	// Generate secret
	secret, err := generator.GenerateSecretDefault()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Validate secret
	err = generator.ValidateSecret(secret)
	assert.NoError(t, err)
}
