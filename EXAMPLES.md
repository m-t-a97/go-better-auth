# Configuration Examples

This document provides comprehensive examples of configuring Go Better Auth using the flexible configuration system.

## Table of Contents
- [Basic Configuration](#basic-configuration)
- [Email and Password Authentication](#email-and-password-authentication)
- [Email Verification](#email-verification)
- [Social Providers](#social-providers)
- [Session Configuration](#session-configuration)
- [Advanced Configuration](#advanced-configuration)
- [Rate Limiting](#rate-limiting)
- [Custom Password Hashing](#custom-password-hashing)
- [Database Hooks](#database-hooks)
- [Complete Example](#complete-example)

## Basic Configuration

The simplest configuration requires only a database:

```go
package main

import (
	"log"
	
	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
)

func main() {
	auth, err := gobetterauth.New(&domain.Config{
		Database: domain.DatabaseConfig{
			Provider:          "sqlite",
			ConnectionString: "./auth.db",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	
	// Use auth.Handler() to get HTTP routes
	_ = auth
}
```

## Email and Password Authentication

Enable email and password authentication with verification:

```go
auth, err := gobetterauth.New(&domain.Config{
	BaseURL: "https://example.com",
	
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: "postgres://user:pass@localhost/dbname?sslmode=disable",
	},
	
	EmailAndPassword: &domain.EmailPasswordConfig{
		Enabled:                  true,
		RequireEmailVerification: true,
		MinPasswordLength:        10,
		MaxPasswordLength:        128,
		AutoSignIn:               true,
		
		SendResetPassword: func(ctx context.Context, user *domain.User, url string, token string) error {
			// Send password reset email
			log.Printf("Password reset for %s: %s", user.Email, url)
			return nil
		},
		
		ResetPasswordTokenExpiresIn: 3600, // 1 hour
	},
})
```

## Email Verification

Configure email verification with custom email sender:

```go
auth, err := gobetterauth.New(&domain.Config{
	BaseURL: "https://example.com",
	
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: "postgres://user:pass@localhost/dbname?sslmode=disable",
	},
	
	EmailVerification: &domain.EmailVerificationConfig{
		SendVerificationEmail: func(ctx context.Context, user *domain.User, url string, token string) error {
			// Send verification email using your email service
			log.Printf("Verification email for %s: %s", user.Email, url)
			// Example: Send email via SendGrid, AWS SES, etc.
			return nil
		},
		
		SendOnSignUp:                    true,
		SendOnSignIn:                    false,
		AutoSignInAfterVerification:     true,
		ExpiresIn:                       3600, // 1 hour
	},
})
```

## Social Providers

Configure multiple OAuth providers:

```go
auth, err := gobetterauth.New(&domain.Config{
	BaseURL: "https://example.com",
	
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	SocialProviders: &domain.SocialProvidersConfig{
		Google: &domain.GoogleProviderConfig{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURI:  "https://example.com/api/auth/callback/google",
		},
		
		GitHub: &domain.GitHubProviderConfig{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			RedirectURI:  "https://example.com/api/auth/callback/github",
		},
		
		// Generic OAuth provider
		Generic: map[string]*domain.GenericOAuthConfig{
			"custom": {
				ClientID:     "custom_client_id",
				ClientSecret: "custom_client_secret",
				RedirectURI:  "https://example.com/api/auth/callback/custom",
				AuthURL:      "https://custom.com/oauth/authorize",
				TokenURL:     "https://custom.com/oauth/token",
				UserInfoURL:  "https://custom.com/oauth/userinfo",
				Scopes:       []string{"openid", "profile", "email"},
				
				UserInfoMapper: func(data map[string]any) *domain.OAuthUserInfo {
					return &domain.OAuthUserInfo{
						ID:    data["sub"].(string),
						Email: data["email"].(string),
						Name:  data["name"].(string),
					}
				},
			},
		},
	},
})
```

## Session Configuration

Customize session behavior:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	Session: &domain.SessionConfig{
		ModelName:             "sessions",
		ExpiresIn:             604800,  // 7 days
		UpdateAge:             86400,   // 1 day
		DisableSessionRefresh: false,
		
		// Map custom field names
		Fields: map[string]string{
			"userId": "user_id",
		},
		
		// Cookie cache for performance
		CookieCache: &domain.CookieCacheConfig{
			Enabled: true,
			MaxAge:  300, // 5 minutes
		},
		
		StoreSessionInDatabase:    true,
		PreserveSessionInDatabase: false,
	},
})
```

## Advanced Configuration

Configure advanced options including CORS, cookies, and security:

```go
auth, err := gobetterauth.New(&domain.Config{
	BaseURL: "https://example.com",
	
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	TrustedOrigins: domain.TrustedOriginsConfig{
		StaticOrigins: []string{
			"https://example.com",
			"https://*.example.com",       // Wildcard subdomain
			"http://localhost:3000",       // Development
		},
	},
	
	Advanced: &domain.AdvancedConfig{
		UseSecureCookies: true,
		
		IPAddress: &domain.IPAddressConfig{
			IPAddressHeaders:  []string{"X-Forwarded-For", "X-Real-IP"},
			DisableIpTracking: false,
		},
		
		CrossSubDomainCookies: &domain.CrossSubDomainCookiesConfig{
			Enabled: true,
			Domain:  ".example.com",
		},
		
		CookiePrefix: "myapp",
		
		DefaultCookieAttributes: &domain.CookieAttributes{
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Lax",
			Path:     "/",
		},
	},
})
```

## Rate Limiting

Configure rate limiting with custom rules:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	RateLimit: &domain.RateLimitOptions{
		Enabled: true,
		Window:  60,   // 60 seconds
		Max:     100,  // 100 requests
		Storage: "memory",
		
		// Custom rules for specific paths
		CustomRules: map[string]domain.RateLimitRule{
			"/api/auth/sign-in": {
				Window: 300,  // 5 minutes
				Max:    5,    // 5 attempts
			},
			"/api/auth/sign-up": {
				Window: 3600, // 1 hour
				Max:    3,    // 3 attempts
			},
		},
	},
})
```

## Custom Password Hashing

Provide custom password hashing functions:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	EmailAndPassword: &domain.EmailPasswordConfig{
		Enabled: true,
		
		Password: &domain.PasswordConfig{
			Hash: func(password string) (string, error) {
				// Use your custom hashing algorithm
				// Example: bcrypt
				hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					return "", err
				}
				return string(hashed), nil
			},
			
			Verify: func(password, hash string) bool {
				// Verify using your custom algorithm
				err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
				return err == nil
			},
		},
	},
})
```

## Database Hooks

Add lifecycle hooks for database operations:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	DatabaseHooks: &domain.DatabaseHooksConfig{
		User: &domain.ModelHooks{
			Create: &domain.CRUDHooks{
				Before: func(ctx context.Context, data interface{}) (interface{}, error) {
					// Modify user data before creation
					log.Println("Creating user...")
					return data, nil
				},
				After: func(ctx context.Context, result interface{}) error {
					// Perform actions after user creation
					log.Println("User created successfully")
					return nil
				},
			},
			Update: &domain.CRUDHooks{
				Before: func(ctx context.Context, data interface{}) (interface{}, error) {
					// Modify user data before update
					log.Println("Updating user...")
					return data, nil
				},
				After: func(ctx context.Context, result interface{}) error {
					// Perform actions after user update
					log.Println("User updated successfully")
					return nil
				},
			},
		},
	},
})
```

## Complete Example

A comprehensive configuration with all major options:

```go
package main

import (
	"context"
	"log"
	"os"
	
	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
)

func main() {
	auth, err := gobetterauth.New(&domain.Config{
		AppName:  "My Application",
		BaseURL:  "https://example.com",
		BasePath: "/api/auth",
		
		Database: domain.DatabaseConfig{
			Provider:          "postgres",
			ConnectionString: os.Getenv("DATABASE_URL"),
			Casing:           "snake",
		},
		
		TrustedOrigins: domain.TrustedOriginsConfig{
			StaticOrigins: []string{
				"https://example.com",
				"https://*.example.com",
				"http://localhost:3000",
			},
		},
		
		EmailVerification: &domain.EmailVerificationConfig{
			SendVerificationEmail: func(ctx context.Context, user *domain.User, url string, token string) error {
				log.Printf("Send verification email to %s: %s", user.Email, url)
				return nil
			},
			SendOnSignUp:                    true,
			AutoSignInAfterVerification:     true,
			ExpiresIn:                       3600,
		},
		
		EmailAndPassword: &domain.EmailPasswordConfig{
			Enabled:                      true,
			RequireEmailVerification:     true,
			MinPasswordLength:            8,
			MaxPasswordLength:            128,
			AutoSignIn:                   true,
			ResetPasswordTokenExpiresIn:  3600,
			
			SendResetPassword: func(ctx context.Context, user *domain.User, url string, token string) error {
				log.Printf("Send password reset to %s: %s", user.Email, url)
				return nil
			},
		},
		
		SocialProviders: &domain.SocialProvidersConfig{
			Google: &domain.GoogleProviderConfig{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURI:  "https://example.com/api/auth/callback/google",
			},
			GitHub: &domain.GitHubProviderConfig{
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
				RedirectURI:  "https://example.com/api/auth/callback/github",
			},
		},
		
		Session: &domain.SessionConfig{
			ExpiresIn:             604800,
			UpdateAge:             86400,
			DisableSessionRefresh: false,
			CookieCache: &domain.CookieCacheConfig{
				Enabled: true,
				MaxAge:  300,
			},
		},
		
		RateLimit: &domain.RateLimitOptions{
			Enabled: true,
			Window:  60,
			Max:     100,
			Storage: "memory",
			CustomRules: map[string]domain.RateLimitRule{
				"/api/auth/sign-in": {Window: 300, Max: 5},
				"/api/auth/sign-up": {Window: 3600, Max: 3},
			},
		},
		
		Advanced: &domain.AdvancedConfig{
			UseSecureCookies: true,
			IPAddress: &domain.IPAddressConfig{
				IPAddressHeaders: []string{"X-Forwarded-For", "X-Real-IP"},
			},
			CrossSubDomainCookies: &domain.CrossSubDomainCookiesConfig{
				Enabled: true,
				Domain:  ".example.com",
			},
		},
		
		Logger: &domain.LoggerConfig{
			Level: domain.LogLevelInfo,
		},
	})
	
	if err != nil {
		log.Fatal(err)
	}
	
	// Use the auth instance
	handler := auth.Handler()
	_ = handler
	
	log.Println("Go Better Auth initialized successfully")
}
```

## Environment Variables

Go Better Auth automatically reads from environment variables:

- `GO_BETTER_AUTH_URL` or `BASE_URL` - Base URL (defaults to BaseURL config)
- `GO_BETTER_AUTH_SECRET` or `AUTH_SECRET` - Secret key for signing (required in production)
- `DATABASE_URL` - Database connection string

Example `.env` file:

```env
GO_BETTER_AUTH_URL=https://example.com
GO_BETTER_AUTH_SECRET=your-secret-key-here
DATABASE_URL=postgres://user:pass@localhost/dbname?sslmode=disable

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

## Default Values

Go Better Auth applies sensible defaults:

- **BaseURL**: `http://localhost:8080`
- **BasePath**: `/api/auth`
- **Session.ExpiresIn**: `604800` seconds (7 days)
- **Session.UpdateAge**: `86400` seconds (1 day)
- **EmailVerification.ExpiresIn**: `3600` seconds (1 hour)
- **EmailAndPassword.MinPasswordLength**: `8`
- **EmailAndPassword.MaxPasswordLength**: `128`
- **RateLimit.Window**: `10` seconds
- **RateLimit.Max**: `100` requests
- **Database.Casing**: `snake`

All these can be overridden in your configuration.
