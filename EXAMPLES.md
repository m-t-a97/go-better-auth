# Configuration Examples

This document provides comprehensive examples of configuring Go Better Auth using the flexible configuration system.

## Table of Contents
- [Basic Configuration](#basic-configuration)
- [Email and Password Authentication](#email-and-password-authentication)
- [Email Verification](#email-verification)
- [Social Providers](#social-providers)
- [Session Configuration](#session-configuration)
- [User Management](#user-management)
- [Account Management](#account-management)
- [Verification Management](#verification-management)
- [Brute Force Protection](#brute-force-protection)
- [Advanced Configuration](#advanced-configuration)
- [Rate Limiting](#rate-limiting)
- [Logging](#logging)
- [Plugins](#plugins)
- [API Error Handling](#api-error-handling)
- [Request Hooks](#request-hooks)
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
		DisableSignUp:            false,
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
		
		Discord: &domain.DiscordProviderConfig{
			ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
			ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
			RedirectURI:  "https://example.com/api/auth/callback/discord",
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

## User Management

Configure user model customization and account management features:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	User: &domain.UserConfig{
		ModelName: "user",
		Fields: map[string]string{
			"email": "email_address",  // Custom field mapping
		},
		
		AdditionalFields: map[string]domain.AdditionalField{
			"phone": {Type: "string"},
		},
		
		ChangeEmail: &domain.ChangeEmailConfig{
			Enabled: true,
			SendChangeEmailVerification: func(ctx context.Context, user *domain.User, newEmail string, url string, token string) error {
				// Implement email sending logic
				log.Printf("Change email for %s to %s: %s", user.Email, newEmail, url)
				return nil
			},
		},
		
		DeleteUser: &domain.DeleteUserConfig{
			Enabled: true,
			SendDeleteAccountVerification: func(ctx context.Context, user *domain.User, url string, token string) error {
				// Implement email sending logic
				log.Printf("Delete account for %s: %s", user.Email, url)
				return nil
			},
			BeforeDelete: func(ctx context.Context, user *domain.User) error {
				// Pre-deletion logic
				log.Println("Deleting user account...")
				return nil
			},
			AfterDelete: func(ctx context.Context, user *domain.User) error {
				// Post-deletion logic
				log.Println("User account deleted successfully")
				return nil
			},
		},
	},
})
```

## Account Management

Configure account linking and OAuth settings:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	Account: &domain.AccountConfig{
		ModelName: "account",
		Fields: map[string]string{
			"userId": "user_id",
		},
		
		EncryptOAuthTokens:   true,
		UpdateAccountOnSignIn: true,
		
		AccountLinking: &domain.AccountLinkingConfig{
			Enabled:             true,
			TrustedProviders:    []string{"google", "github"},
			AllowDifferentEmails: false,
			AllowUnlinkingAll:    false,
		},
	},
})
```

## Verification Management

Configure verification token storage:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	Verification: &domain.VerificationConfig{
		ModelName: "verification",
		Fields: map[string]string{
			"token": "verification_token",
		},
		DisableCleanup: false,
	},
})
```

## Brute Force Protection

Configure brute force protection:

```go
import (
	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/domain/security"
)

auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	BruteForce: &security.BruteForceConfig{
		Enabled:          true,
		MaxAttempts:      5,
		Window:           900,    // 15 minutes
		BlockDuration:    3600,   // 1 hour
		CleanupInterval:  3600,   // 1 hour
		Storage:          "memory",
	},
})
```

## Logging

Configure logging behavior:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	Logger: &domain.LoggerConfig{
		Disabled:     false,
		DisableColors: false,
		Level:        domain.LogLevelInfo,  // "debug", "info", "warn", "error"
		
		Log: func(level domain.LogLevel, message string, args ...interface{}) {
			// Custom logging implementation
			log.Printf("[%s] %s", level, fmt.Sprintf(message, args...))
		},
	},
})
```

## Plugins

Extend functionality with plugins:

```go
// Define a custom plugin
type CustomPlugin struct{}

func (p *CustomPlugin) Name() string {
	return "custom"
}

func (p *CustomPlugin) Initialize(config interface{}) error {
	// Initialize plugin
	return nil
}

auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	Plugins: []domain.Plugin{
		&CustomPlugin{},
	},
})
```

## API Error Handling

Configure custom error handling:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	OnAPIError: &domain.OnAPIErrorConfig{
		Throw:    false,
		OnError: func(err error, ctx context.Context) {
			// Custom error handling logic
			log.Printf("API Error: %v", err)
		},
		ErrorURL: "/api/auth/error",
	},
})
```

## Request Hooks

Add request lifecycle hooks:

```go
auth, err := gobetterauth.New(&domain.Config{
	Database: domain.DatabaseConfig{
		Provider:          "postgres",
		ConnectionString: os.Getenv("DATABASE_URL"),
	},
	
	Hooks: &domain.HooksConfig{
		Before: func(ctx *domain.RequestContext) error {
			// Pre-request logic
			log.Printf("Request: %s %s", ctx.Method, ctx.Path)
			return nil
		},
		After: func(ctx *domain.RequestContext) error {
			// Post-request logic
			log.Printf("Response: %s %s", ctx.Method, ctx.Path)
			return nil
		},
	},
	
	DisabledPaths: []string{
		"/api/auth/debug",  // Disable specific paths
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
		Enabled:  true,
		Window:   60,   // 60 seconds
		Max:      100,  // 100 requests
		Algorithm: "fixed-window", // "fixed-window" or "sliding-window"
		Storage:  "memory",
		
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
			DisableSignUp:                false,
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
			Discord: &domain.DiscordProviderConfig{
				ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
				ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
				RedirectURI:  "https://example.com/api/auth/callback/discord",
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
			Enabled:   true,
			Window:    60,
			Max:       100,
			Algorithm: "fixed-window",
			Storage:   "memory",
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
		
		User: &domain.UserConfig{
			ChangeEmail: &domain.ChangeEmailConfig{
				Enabled: true,
				SendChangeEmailVerification: func(ctx context.Context, user *domain.User, newEmail string, url string, token string) error {
					log.Printf("Send change email to %s: %s", user.Email, url)
					return nil
				},
			},
			DeleteUser: &domain.DeleteUserConfig{
				Enabled: true,
				SendDeleteAccountVerification: func(ctx context.Context, user *domain.User, url string, token string) error {
					log.Printf("Send delete account to %s: %s", user.Email, url)
					return nil
				},
			},
		},
		
		Account: &domain.AccountConfig{
			EncryptOAuthTokens:   true,
			UpdateAccountOnSignIn: true,
			AccountLinking: &domain.AccountLinkingConfig{
				Enabled:          true,
				TrustedProviders: []string{"google", "github"},
			},
		},
		
		Verification: &domain.VerificationConfig{
			DisableCleanup: false,
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

DISCORD_CLIENT_ID=your-discord-client-id
DISCORD_CLIENT_SECRET=your-discord-client-secret
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

## HTTP Router Integration

### Standard Library (net/http)

```go
package main

import (
	"log"
	"net/http"

	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
)

func main() {
	auth, err := gobetterauth.New(&domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "your-secret-key-here",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: "./auth.db",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Mount handler on stdlib mux
	http.Handle("/api/auth/", auth.Handler())

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Chi Router

```go
package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
)

func main() {
	auth, err := gobetterauth.New(&domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "your-secret-key-here",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: "./auth.db",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()

	// Mount auth handler on Chi router
	r.Mount("/api/auth", http.StripPrefix("/api/auth", auth.Handler()))

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

### Echo Router

```go
package main

import (
	"log"

	"github.com/labstack/echo/v4"
	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
)

func main() {
	auth, err := gobetterauth.New(&domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "your-secret-key-here",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: "./auth.db",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	e := echo.New()

	// Mount auth handler on Echo router
	e.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))

	log.Println("Server running on http://localhost:8080")
	log.Fatal(e.Start(":8080"))
}
```

### Gin Router

```go
package main

import (
	"log"

	"github.com/gin-gonic/gin"
	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
)

func main() {
	auth, err := gobetterauth.New(&domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "your-secret-key-here",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: "./auth.db",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()

	// Mount auth handler on Gin router
	r.Any("/api/auth/*path", gin.WrapH(auth.Handler()))

	log.Println("Server running on http://localhost:8080")
	log.Fatal(r.Run(":8080"))
}
```

### Fiber Router

```go
package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
)

func main() {
	auth, err := gobetterauth.New(&domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "your-secret-key-here",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: "./auth.db",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	app := fiber.New()

	// Mount auth handler on Fiber router
	app.Use("/api/auth", func(c *fiber.Ctx) error {
		return auth.Handler().ServeHTTP(c.Response().Writer, c.Request())
	})

	log.Println("Server running on http://localhost:8080")
	log.Fatal(app.Listen(":8080"))
}
```

---
