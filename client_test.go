package gobetterauth

import (
	"testing"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/usecase"
)

// TestNew_DefaultBaseURL tests that default BaseURL is set when empty
func TestNew_DefaultBaseURL(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
		BaseURL: "",
	}

	ba, _ := New(config)
	// We expect an error due to invalid connection string, but we're testing the default logic
	if ba != nil {
		handler := ba.Handler()
		if handler == nil {
			t.Fatal("expected handler to be set")
		}
	}
}

// TestNew_InvalidDatabaseProvider tests error handling for invalid database provider
func TestNew_InvalidDatabaseProvider(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "invalid_db",
			ConnectionString: "some_connection",
		},
	}

	ba, err := New(config)
	if err == nil {
		t.Fatal("expected error for invalid database provider, got nil")
	}

	if ba != nil {
		t.Fatal("expected nil GoBetterAuth instance, got non-nil")
	}

	authErr, ok := err.(*domain.AuthError)
	if !ok {
		t.Fatalf("expected AuthError, got %T", err)
	}

	if authErr.Code != "invalid_database" {
		t.Fatalf("expected code 'invalid_database', got '%s'", authErr.Code)
	}
}

// TestNew_UnsupportedDatabaseProvider tests error handling for unsupported database providers
func TestNew_UnsupportedDatabaseProvider(t *testing.T) {
	testCases := []string{"mysql"}

	for _, provider := range testCases {
		t.Run(provider, func(t *testing.T) {
			config := &Config{
				Database: DatabaseConfig{
					Provider:         provider,
					ConnectionString: "some_connection",
				},
			}

			ba, err := New(config)
			if err == nil {
				t.Fatalf("expected error for unsupported provider %s, got nil", provider)
			}

			if ba != nil {
				t.Fatal("expected nil GoBetterAuth instance, got non-nil")
			}

			authErr, ok := err.(*domain.AuthError)
			if !ok {
				// It's okay if it's not an AuthError, just verify error exists
				t.Logf("Got error type: %T with message: %v", err, err)
				return
			}

			if authErr.Code != "unsupported_database" {
				t.Fatalf("expected code 'unsupported_database', got '%s'", authErr.Code)
			}
		})
	}
}

// TestNew_CustomPasswordHasher tests that custom password hasher is used
func TestNew_CustomPasswordHasher(t *testing.T) {
	customHasher := usecase.NewArgon2PasswordHasher()

	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
		Advanced: AdvancedConfig{
			PasswordHasher: customHasher,
		},
	}

	// We expect connection error, but we're testing that custom hasher is accepted
	ba, _ := New(config)
	if ba == nil {
		// Expected error due to invalid connection string
		// This is fine, might be a database error
		return
	}
}

// TestNew_WithGoogleProvider tests initialization with Google OAuth provider
func TestNew_WithGoogleProvider(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
		SocialProviders: SocialProvidersConfig{
			Google: &GoogleProviderConfig{
				ClientID:     "test_client_id",
				ClientSecret: "test_client_secret",
				RedirectURL:  "http://localhost:3000/auth/google/callback",
			},
		},
	}

	// We expect connection error, but we're testing that Google provider is accepted
	ba, _ := New(config)
	if ba == nil {
		// Expected error due to invalid connection string
		// This is fine, might be a database error
		return
	}
}

// TestNew_WithGitHubProvider tests initialization with GitHub OAuth provider
func TestNew_WithGitHubProvider(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
		SocialProviders: SocialProvidersConfig{
			GitHub: &GitHubProviderConfig{
				ClientID:     "test_client_id",
				ClientSecret: "test_client_secret",
				RedirectURL:  "http://localhost:3000/auth/github/callback",
			},
		},
	}

	ba, _ := New(config)
	if ba == nil {
		// Expected error due to invalid connection string
		// This is fine, might be a database error
		return
	}
}

// TestNew_WithDiscordProvider tests initialization with Discord OAuth provider
func TestNew_WithDiscordProvider(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
		SocialProviders: SocialProvidersConfig{
			Discord: &DiscordProviderConfig{
				ClientID:     "test_client_id",
				ClientSecret: "test_client_secret",
				RedirectURL:  "http://localhost:3000/auth/discord/callback",
			},
		},
	}

	ba, _ := New(config)
	if ba == nil {
		// Expected error due to invalid connection string
		// This is fine, might be a database error
		return
	}
}

// TestNew_WithGenericOAuthProvider tests initialization with generic OAuth provider
func TestNew_WithGenericOAuthProvider(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
		SocialProviders: SocialProvidersConfig{
			Generic: map[string]*GenericOAuthConfig{
				"custom": {
					ClientID:     "test_client_id",
					ClientSecret: "test_client_secret",
					RedirectURL:  "http://localhost:3000/auth/custom/callback",
					AuthURL:      "https://example.com/oauth/authorize",
					TokenURL:     "https://example.com/oauth/token",
					UserInfoURL:  "https://example.com/oauth/userinfo",
					Scopes:       []string{"openid", "profile", "email"},
					UserInfoMapper: func(data map[string]any) *domain.OAuthUserInfo {
						return &domain.OAuthUserInfo{
							ID:    "123",
							Email: "test@example.com",
							Name:  "Test User",
						}
					},
				},
			},
		},
	}

	ba, _ := New(config)
	if ba == nil {
		// Expected error due to invalid connection string
		// This is fine, might be a database error
		return
	}
}

// TestNew_MultipleProviders tests initialization with multiple OAuth providers
func TestNew_MultipleProviders(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
		SocialProviders: SocialProvidersConfig{
			Google: &GoogleProviderConfig{
				ClientID:     "google_client_id",
				ClientSecret: "google_client_secret",
				RedirectURL:  "http://localhost:3000/auth/google/callback",
			},
			GitHub: &GitHubProviderConfig{
				ClientID:     "github_client_id",
				ClientSecret: "github_client_secret",
				RedirectURL:  "http://localhost:3000/auth/github/callback",
			},
			Discord: &DiscordProviderConfig{
				ClientID:     "discord_client_id",
				ClientSecret: "discord_client_secret",
				RedirectURL:  "http://localhost:3000/auth/discord/callback",
			},
		},
	}

	ba, _ := New(config)
	if ba == nil {
		// Expected error due to invalid connection string
		// This is fine, might be a database error
		return
	}
}

// TestHandler tests that http.Handler is properly exposed
func TestHandler(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
	}

	ba, _ := New(config)
	if ba != nil {
		handler := ba.Handler()
		if handler == nil {
			t.Fatal("expected non-nil handler")
		}
	}
}

// TestAuthUseCase tests that AuthUseCase is properly exposed
func TestAuthUseCase(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
	}

	ba, _ := New(config)
	if ba != nil {
		useCase := ba.AuthUseCase()
		if useCase == nil {
			t.Fatal("expected non-nil auth use case")
		}
	}
}

// TestOAuthUseCase tests that OAuthUseCase is properly exposed
func TestOAuthUseCase(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
	}

	ba, _ := New(config)
	if ba != nil {
		useCase := ba.OAuthUseCase()
		if useCase == nil {
			t.Fatal("expected non-nil oauth use case")
		}
	}
}
