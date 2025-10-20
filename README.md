# Go Better Auth 🔐

A comprehensive, framework-agnostic authentication and authorization library for Go, inspired by [Better Auth](https://better-auth.com). Built with clean architecture principles, SOLID design patterns, and Go best practices.

## ✨ Features

- 🔑 **Email & Password Authentication** - Built-in support with secure password hashing (scrypt)
- 🌐 **Social OAuth Providers** - Google, GitHub, Discord, and extensible generic OAuth2 support
- 🔐 **Session Management** - Secure session handling with customizable expiration and refresh
- ✉️ **Email Verification** - Optional email verification workflow
- 🔄 **Password Reset** - Secure password reset functionality
- 🏗️ **Clean Architecture** - Separation of concerns with domain, usecase, delivery, and infrastructure layers
- 🔌 **Plugin System** - Extensible architecture for adding custom functionality
- 💾 **Multiple Database Support** - PostgreSQL, SQLite (via adapters), more coming soon...
- 🛡️ **Security First** - CSRF protection, secure cookies, rate limiting support
- 📦 **Zero Dependencies** - Minimal external dependencies, production-ready
- ⚡ **Rate Limiting** - Redis-based rate limiting for API endpoints
- 🔐 **Multi-Factor Authentication (MFA)** - Optional TOTP-based MFA for enhanced security
- 🔄 **Refresh Tokens** - Full OAuth refresh token support with automatic expiration management
- 🎫 **JWT Support** - RS256-based JWT token management with key rotation
- 🔁 **Token Refresh Flow** - Automatic token refresh and session extension capabilities

## 🚀 Quick Start

### Installation

```bash
go get github.com/m-t-a97/go-better-auth
```

### Basic Usage

```go
package main

import (
    "log"
    "net/http"
    "time"
    
    "github.com/m-t-a97/go-better-auth/pkg/gobetterauth"
)

func main() {
    // Configure Go Better Auth
    config := &gobetterauth.Config{
        BaseURL: "http://localhost:3000",
        
        Database: gobetterauth.DatabaseConfig{
            Provider:         "postgres",
            ConnectionString: "postgres://user:password@localhost/dbname?sslmode=disable",
        },
        
        EmailAndPassword: gobetterauth.EmailPasswordConfig{
            Enabled:    true,
            AutoSignIn: true,
            SendVerificationEmail: func(email, token, url string) error {
                // Implement your email sending logic
                return nil
            },
        },
        
        Session: gobetterauth.SessionConfig{
            ExpiresIn: 7 * 24 * time.Hour,
        },
        
        SocialProviders: gobetterauth.SocialProvidersConfig{
            Google: &gobetterauth.GoogleProviderConfig{
                ClientID:     "your-client-id",
                ClientSecret: "your-client-secret",
                RedirectURL:  "http://localhost:3000/api/auth/oauth/google/callback",
            },
        },
    }
    
    // Initialize Go Better Auth
    auth, err := gobetterauth.New(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Mount auth routes
    http.Handle("/api/auth/", auth.Handler())
    
    // Start server
    log.Println("Server starting on :3000")
    log.Fatal(http.ListenAndServe(":3000", nil))
}
```

### Detailed Setup and Initialization

Go Better Auth is initialized via the `gobetterauth.New(config)` function, which takes a `Config` struct. The library follows a layered architecture: the domain layer defines core entities and interfaces, the usecase layer handles business logic, the delivery layer manages HTTP interactions, and the infrastructure layer connects to databases and external services.

1. **Configuration**: Populate the `Config` struct with your settings. Required fields include `BaseURL` and `Database`. Optional fields like `EmailAndPassword`, `Session`, and `SocialProviders` enable specific features.
2. **Database Setup**: Run migrations from the `migrations/` folder to set up tables for users, sessions, accounts, and verifications. Supported providers: PostgreSQL, SQLite.
3. **Email Integration**: For features like verification or password reset, provide callback functions (e.g., `SendVerificationEmail`) to handle email sending.
4. **Session Handling**: Sessions are managed via secure cookies or tokens. Customize expiration in `SessionConfig`.
5. **OAuth Setup**: Configure client IDs, secrets, and redirect URLs for social providers. The library handles OAuth flows automatically.
6. **Plugins**: Optionally add plugins via the `Plugins` field in config for custom routes or logic.
7. **Rate Limiting and MFA**: See dedicated sections below for setup.
8. **Initialization**: Call `gobetterauth.New(config)` to create an auth instance. Mount routes with `auth.Handler()`. The library is thread-safe and ready for production.

## 📚 Core Concepts

### How the Library Works

Go Better Auth operates as a middleware-like library that integrates into your Go HTTP server. It provides endpoints for authentication flows, manages state via sessions, and enforces security through hashing, CSRF protection, and optional rate limiting.

- **Authentication Flow**: Users sign up/in via email/password or OAuth. Sessions are created and stored securely. Verification and resets are handled via email tokens.
- **Security Mechanisms**: Passwords are hashed with scrypt. Sessions use secure tokens. CSRF tokens protect against cross-site requests.
- **Extensibility**: Use plugins to add custom endpoints. Adapters allow database swapping.
- **Error Handling**: Domain-specific errors are returned for invalid credentials, expired sessions, etc.

#### Authentication Methods

##### Email & Password

```go
config := &gobetterauth.Config{
    EmailAndPassword: gobetterauth.EmailPasswordConfig{
        Enabled:                  true,
        RequireEmailVerification: false,
        AutoSignIn:               true,
    },
}
```

**Client Usage:**
```bash
# Sign Up
curl -X POST http://localhost:3000/api/auth/sign-up/email \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secure123","name":"John Doe"}'

# Sign In
curl -X POST http://localhost:3000/api/auth/sign-in/email \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secure123"}'

# Sign Out
curl -X POST http://localhost:3000/api/auth/sign-out \
  -H "Cookie: better-auth.session_token=your-token"
```

#### OAuth Social Providers

Supported providers:
- **Google** - OpenID Connect
- **GitHub** - OAuth 2.0
- **Discord** - OAuth 2.0
- **Generic OAuth2** - Extensible for any provider

```go
SocialProviders: gobetterauth.SocialProvidersConfig{
    Google: &gobetterauth.GoogleProviderConfig{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:3000/api/auth/oauth/google/callback",
    },
    GitHub: &gobetterauth.GitHubProviderConfig{
        ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
        ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:3000/api/auth/oauth/github/callback",
    },
}
```

**Client Usage:**
```bash
# Initiate OAuth flow
GET http://localhost:3000/api/auth/oauth/google

# Callback (handled automatically)
GET http://localhost:3000/api/auth/oauth/google/callback?code=...
```

### Session Management

```go
// Get current session
session, user, err := auth.AuthUseCase().GetSession(ctx, token)
if err != nil {
    // Handle error
}

// Sign out (invalidate session)
err = auth.AuthUseCase().SignOut(ctx, token)
```

### Email Verification

```go
EmailAndPassword: gobetterauth.EmailPasswordConfig{
    RequireEmailVerification: true,
    SendVerificationEmail: func(email, token, url string) error {
        // Send email with verification link
        return sendEmail(email, "Verify your email", url)
    },
}
```

**API Endpoints:**
```bash
# Send verification email
POST /api/auth/send-verification-email
{"email": "user@example.com"}

# Verify email
GET /api/auth/verify-email?token=verification-token
```

### Password Reset

```go
EmailAndPassword: gobetterauth.EmailPasswordConfig{
    SendPasswordResetEmail: func(email, token, url string) error {
        // Send password reset email
        return sendEmail(email, "Reset your password", url)
    },
}
```

**API Endpoints:**
```bash
# Request password reset
POST /api/auth/request-password-reset
{"email": "user@example.com"}

# Reset password
POST /api/auth/reset-password
{"token": "reset-token", "newPassword": "newsecure123"}

# Change password (requires authentication)
POST /api/auth/change-password
{"currentPassword": "old123", "newPassword": "new123", "revokeOtherSessions": true}
```

## ⚡ Rate Limiting

Go Better Auth supports Redis-based rate limiting to prevent abuse on authentication endpoints.

### Setup

1. Install and run Redis.
2. Add to config:

```go
config := &gobetterauth.Config{
    // ...existing config...
    RateLimit: gobetterauth.RateLimitConfig{
        Enabled: true,
        RedisURL: "redis://localhost:6379",
        MaxRequests: 10, // per window
        Window: 1 * time.Minute,
    },
}
```

3. The library automatically applies limits to sign-up, sign-in, and OAuth endpoints. Exceeded requests return 429 status.

## 🔐 Multi-Factor Authentication (MFA)

Optional TOTP-based MFA adds a second verification layer.

### Setup

1. Enable in config:

```go
config := &gobetterauth.Config{
    // ...existing config...
    MFA: gobetterauth.MFAConfig{
        Enabled: true,
        Issuer: "YourApp", // For TOTP apps like Google Authenticator
    },
}
```

2. After sign-in, users can enable MFA via `/api/auth/enable-mfa` (requires session). This generates a secret and QR code.
3. On subsequent logins, provide TOTP code via `/api/auth/verify-mfa`.

**API Endpoints:**
```bash
# Enable MFA
POST /api/auth/enable-mfa
# Returns: {"secret": "...", "qrCodeURL": "..."}

# Verify MFA (during login)
POST /api/auth/verify-mfa
{"code": "123456"}
```

## 🔄 Token Refresh & Management

Go Better Auth provides comprehensive token refresh functionality for both OAuth and session tokens.

### OAuth Token Refresh

Automatically refresh OAuth access tokens when expired:

```go
// Refresh OAuth access token
output, err := oauthUseCase.RefreshToken(ctx, &usecase.RefreshTokenInput{
    UserID:   user.ID,
    Provider: "google",
})

if err != nil {
    // Token expired or no refresh token available
}

// Use new tokens
accessToken := output.AccessToken
refreshToken := output.RefreshToken
expiresIn := output.ExpiresIn
```

**API Endpoint:**
```bash
# Refresh OAuth tokens (requires authentication)
POST /api/auth/oauth/{provider}/refresh
Authorization: Bearer {session_token}

# Response:
{
  "accessToken": "new-access-token",
  "refreshToken": "refresh-token",
  "idToken": "id-token",
  "expiresIn": 3600
}
```

### Session Refresh

Extend session expiration automatically:

```go
// Refresh session
output, err := authUseCase.RefreshSession(ctx, &usecase.RefreshSessionInput{
    Token: sessionToken,
})

if err != nil {
    // Session expired
}

// Session is now extended
newExpiresAt := output.Session.ExpiresAt
```

**API Endpoint:**
```bash
# Refresh session
POST /api/auth/session/refresh
Authorization: Bearer {session_token}

# Response:
{
  "user": {...},
  "session": {
    "id": "...",
    "token": "...",
    "expiresAt": "2025-10-21T10:00:00Z",
    ...
  }
}
```

### Clean Expired Sessions

Automatically clean up expired sessions:

```go
// Clean expired sessions from database
err := authUseCase.CleanExpiredSessions(ctx)
```

Run this periodically (e.g., via cron job) to maintain database performance.

## 🎫 JWT Token Management

Go Better Auth includes full JWT support with RS256 signing for enhanced security.

### Setup

```go
import "github.com/m-t-a97/go-better-auth/pkg/jwt"

// Create JWT manager with auto-generated RSA keys
jwtManager, err := jwt.NewManager("https://example.com", []string{"https://example.com"})

// Or load from existing keys
jwtManager, err := jwt.NewManagerWithKeys(privateKey, publicKey, "https://example.com", []string{"https://example.com"})

// Export keys for persistent storage
privateKey, publicKey, err := jwtManager.ExportKeys()
```

### Create Tokens

```go
// Create access and refresh token pair
tokenPair, err := jwtManager.CreateTokenPair(
    user.ID,
    user.Email,
    user.Name,
    15 * time.Minute,  // access token expiry
    7 * 24 * time.Hour, // refresh token expiry
)

// Or OAuth-specific tokens
tokenPair, err := jwtManager.CreateOAuthTokenPair(
    user.ID,
    user.Email,
    user.Name,
    "google",               // provider
    oauthAccountID,         // OAuth account ID
    15 * time.Minute,
    7 * 24 * time.Hour,
)
```

### Verify & Refresh

```go
// Verify token validity
claims, err := jwtManager.VerifyToken(tokenString)

// Refresh access token using refresh token
newAccessToken, err := jwtManager.RefreshAccessToken(refreshToken, 15 * time.Minute)

// Check if token is expired
isExpired := jwtManager.IsTokenExpired(tokenString)

// Get remaining time
remaining := jwtManager.GetRemainingTime(tokenString)
```

## 🏗️ Architecture

Go Better Auth follows **Clean Architecture** principles:

```
go-better-auth/
├── internal/                 # Internal packages
│   ├── domain/              # Domain layer (entities, interfaces)
│   │   ├── models.go
│   │   └── errors.go
│   ├── usecase/             # Business logic layer
│   │   ├── auth_usecase.go
│   │   └── oauth_usecase.go
│   ├── delivery/            # Delivery layer (HTTP, gRPC, etc.)
│   │   └── http/
│   │       └── handler.go
│   └── infrastructure/      # Infrastructure layer (DB, external services)
│       └── postgres/
│           └── adapter.go
└── pkg/                     # Public packages
    ├── gobetterauth/          # Main library interface
    │   └── gobetterauth.go
    └── plugin/              # Plugin system
        └── plugin.go
```

### Layers

1. **Domain Layer** (`internal/domain/`)
   - Core entities: User, Session, Account, Verification
   - Repository interfaces
   - Domain errors

2. **Use Case Layer** (`internal/usecase/`)
   - Business logic for authentication flows
   - OAuth provider implementations
   - Password hashing utilities

3. **Delivery Layer** (`internal/delivery/`)
   - HTTP handlers and routes
   - Request/response models
   - Middleware

4. **Infrastructure Layer** (`internal/infrastructure/`)
   - Database adapters (PostgreSQL, MySQL, SQLite)
   - External service integrations

5. **Public API** (`pkg/`)
   - GoBetterAuth configuration and builder
   - Plugin system interface

## 🔌 Plugin System

Create custom plugins to extend functionality:

```go
package main

import (
    "net/http"
    "github.com/m-t-a97/go-better-auth/pkg/plugin"
)

type CustomPlugin struct {
    plugin.BasePlugin
}

func NewCustomPlugin() *CustomPlugin {
    return &CustomPlugin{
        BasePlugin: plugin.BasePlugin{Name: "custom"},
    }
}

func (p *CustomPlugin) Initialize(config *plugin.PluginConfig) error {
    // Initialize plugin
    return nil
}

func (p *CustomPlugin) RegisterRoutes(router plugin.Router) {
    router.Post("/api/auth/custom-action", p.handleCustomAction)
}

func (p *CustomPlugin) handleCustomAction(w http.ResponseWriter, r *http.Request) {
    // Custom logic
}
```

## 💾 Database Adapters

### PostgreSQL

```go
Database: gobetterauth.DatabaseConfig{
    Provider:         "postgres",
    ConnectionString: "postgres://user:password@localhost/dbname?sslmode=disable",
}
```

**Schema Migration:**

You can find the files in `migrations/` folder.

### CSRF Protection

Automatic CSRF token validation for state-changing operations.

## 🌟 Examples

See the `examples/` directory for complete examples:

- Basic email/password authentication
- OAuth integration
- Custom plugin development
- Multi-provider setup

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Follow Go best practices and conventions
2. Maintain clean architecture principles
3. Add tests for new features
4. Update documentation

## 📄 License

MIT License - see LICENSE file for details

## 📞 Support

- GitHub Issues: [Report bugs or request features](https://github.com/m-t-a97/go-better-auth/issues)
- Documentation: [Full documentation](https://github.com/m-t-a97/go-better-auth/wiki)

---
