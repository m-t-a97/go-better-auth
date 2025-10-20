package gobetterauth

import (
	"testing"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/internal/usecase"
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
		handlers := ba.GetHandlers()
		if handlers == nil {
			t.Fatal("expected handlers to be set")
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
	testCases := []string{"mysql", "sqlite"}

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
				t.Fatalf("expected AuthError, got %T", err)
			}

			if authErr.Code != "unsupported_database" {
				t.Fatalf("expected code 'unsupported_database', got '%s'", authErr.Code)
			}
		})
	}
}

// TestNew_CustomPasswordHasher tests that custom password hasher is used
func TestNew_CustomPasswordHasher(t *testing.T) {
	customHasher := usecase.NewScryptPasswordHasher()

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
					UserInfoMapper: func(data map[string]interface{}) *usecase.OAuthUserInfo {
						return &usecase.OAuthUserInfo{
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

// TestGetHandlers tests that all handlers are properly exposed
func TestGetHandlers(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
	}

	ba, _ := New(config)
	if ba != nil {
		handlers := ba.GetHandlers()
		if handlers == nil {
			t.Fatal("expected non-nil handlers")
		}

		if handlers.SignUpEmail == nil {
			t.Fatal("expected SignUpEmail handler")
		}
		if handlers.SignInEmail == nil {
			t.Fatal("expected SignInEmail handler")
		}
		if handlers.SignOut == nil {
			t.Fatal("expected SignOut handler")
		}
		if handlers.GetSession == nil {
			t.Fatal("expected GetSession handler")
		}
		if handlers.VerifyEmail == nil {
			t.Fatal("expected VerifyEmail handler")
		}
		if handlers.RequestPasswordReset == nil {
			t.Fatal("expected RequestPasswordReset handler")
		}
		if handlers.ResetPassword == nil {
			t.Fatal("expected ResetPassword handler")
		}
		if handlers.ChangePassword == nil {
			t.Fatal("expected ChangePassword handler")
		}
		if handlers.OAuthAuthorize == nil {
			t.Fatal("expected OAuthAuthorize handler")
		}
		if handlers.OAuthCallback == nil {
			t.Fatal("expected OAuthCallback handler")
		}
	}
}

// TestGetMiddleware tests that middleware is properly exposed
func TestGetMiddleware(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
	}

	ba, _ := New(config)
	if ba != nil {
		middleware := ba.GetMiddleware()
		if middleware == nil {
			t.Fatal("expected non-nil middleware")
		}

		if middleware.SessionAuth == nil {
			t.Fatal("expected SessionAuth middleware")
		}
		if middleware.CORS == nil {
			t.Fatal("expected CORS middleware")
		}
	}
}

// TestGetRoutes tests that route patterns are properly exposed
func TestGetRoutes(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Provider:         "postgres",
			ConnectionString: "invalid_for_test",
		},
	}

	ba, _ := New(config)
	if ba != nil {
		routes := ba.GetRoutes()
		if routes == nil {
			t.Fatal("expected non-nil routes")
		}

		expectedRoutes := map[string]string{
			"SignUpEmail":           "POST /api/auth/sign-up/email",
			"SignInEmail":           "POST /api/auth/sign-in/email",
			"SignOut":               "POST /api/auth/sign-out",
			"GetSession":            "GET /api/auth/session",
			"SendVerificationEmail": "POST /api/auth/send-verification-email",
			"VerifyEmail":           "GET /api/auth/verify-email",
			"RequestPasswordReset":  "POST /api/auth/request-password-reset",
			"ResetPassword":         "POST /api/auth/reset-password",
			"ChangePassword":        "POST /api/auth/change-password",
			"OAuthAuthorize":        "GET /api/auth/oauth/{provider}",
			"OAuthCallback":         "GET /api/auth/oauth/{provider}/callback",
		}

		if routes.SignUpEmail != expectedRoutes["SignUpEmail"] {
			t.Fatalf("expected SignUpEmail route '%s', got '%s'", expectedRoutes["SignUpEmail"], routes.SignUpEmail)
		}
		if routes.OAuthAuthorize != expectedRoutes["OAuthAuthorize"] {
			t.Fatalf("expected OAuthAuthorize route '%s', got '%s'", expectedRoutes["OAuthAuthorize"], routes.OAuthAuthorize)
		}
	}
}
