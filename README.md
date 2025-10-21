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

---

## 🚀 Quick Start

### Installation

```bash
go get github.com/m-t-a97/go-better-auth
```

### Basic Usage

Use go-better-auth as a complete authentication framework with built-in HTTP handlers:

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/m-t-a97/go-better-auth"
)

func main() {
    config := &gobetterauth.Config{
        BaseURL: "http://localhost:8080",
        Database: gobetterauth.DatabaseConfig{
            Provider:         "sqlite",
            ConnectionString: ":memory:",
        },
        EmailAndPassword: gobetterauth.EmailPasswordConfig{
            Enabled:    true,
            AutoSignIn: true,
        },
    }
    
    auth, err := gobetterauth.New(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Mount built-in HTTP handlers for all auth endpoints
    http.Handle("/api/auth/", auth.Handler())
    
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Detailed Setup and Initialization

Go Better Auth is initialized via the `gobetterauth.New(config)` function, which takes a `Config` struct. The library provides built-in HTTP handlers that implement all authentication endpoints.

**Architecture Overview:**
```
┌─────────────────────────┐
│ Your Application        │
│ (any HTTP server)       │
└────────────┬────────────┘
             │ mounts
             │
       ┌─────▼──────────┐
       │ auth.Handler() │
       │ (http.Handler) │
       └─────┬──────────┘
             │
       ┌─────▼──────────┐
       │ Domain Layer   │
       │ Repositories   │
       │ Use Cases      │
       │ Services       │
       └─────┬──────────┘
             │
       ┌─────▼────────────┐
       │ Database Adapters│
       │ (PostgreSQL, etc)│
       └──────────────────┘
```

---

**Setup Steps:**

1. **Configuration**: Populate the `Config` struct with your settings. Required: `BaseURL`, `Database`
2. **Database Setup**: Run migrations from `migrations/` folder
3. **Email Integration**: Provide callbacks for email sending
4. **Session Configuration**: Customize expiration in `SessionConfig`
5. **OAuth Setup**: Configure provider credentials and redirect URLs
6. **Initialization**: Call `gobetterauth.New(config)`
7. **Mount Handler**: Use `auth.Handler()` to get built-in handlers and mount on your HTTP server
8. **Deploy**: The library is thread-safe and production-ready

---

## ⚡ Rate Limiting

Go Better Auth includes built-in rate limiting for authentication endpoints when enabled in configuration.

### Setup

1. Install and run Redis (or configure your backend).
2. Add to config:

```go
config := &gobetterauth.Config{
    // ...existing config...
    RateLimit: gobetterauth.RateLimitConfig{
        Enabled:     true,
        RedisURL:    "redis://localhost:6379",
        MaxRequests: 10, // per window
        Window:      1 * time.Minute,
    },
}
```

The built-in handlers will automatically apply rate limiting to prevent abuse. Exceeded rate limits return HTTP 429 (Too Many Requests).

---

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

The built-in handlers will automatically handle MFA enrollment, verification, and management endpoints.

---

## 🔄 Token Refresh & Management

Go Better Auth provides comprehensive token refresh functionality for both OAuth and session tokens. The built-in handlers automatically handle token refresh endpoints.

---

### OAuth Token Refresh

OAuth access tokens are automatically refreshed by the built-in handlers when they expire.

---

### Session Refresh

Session tokens are automatically refreshed by the built-in handlers to extend user sessions.

---

### Clean Expired Sessions

The library automatically manages expired sessions. For manual cleanup, you can periodically clean expired sessions from the database using the internal cleanup mechanisms.

---

## 🎫 JWT Token Management

Go Better Auth includes full JWT support with RS256 signing for enhanced security.

### Setup

```go
import "github.com/m-t-a97/go-better-auth/jwt"

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

---

## 🏗️ Architecture

Go Better Auth follows **Clean Architecture** principles with built-in HTTP handlers:

```
┌────────────────────────────────────────────────────┐
│          Go Better Auth Library                    │
├────────────────────────────────────────────────────┤
│  Standalone HTTP Handlers                          │
│  • Built-in http.Handler implementation            │
│  • auth.Handler() returns ready-to-use handler     │
│  • Mount on any standard HTTP server               │
├────────────────────────────────────────────────────┤
│  Core Components                                   │
│  • Domain Models (User, Session, Account, etc.)    │
│  • Use Cases (business logic)                      │
│  • Repositories (data persistence interfaces)      │
│  • Services (CSRF, Rate Limiting, MFA, JWT)        │
├────────────────────────────────────────────────────┤
│  Database Adapters                                 │
│  • PostgreSQL • SQLite • Extensible                │
└────────────────────────────────────────────────────┘
```

**Key Design Principles:**

1. **Framework-Agnostic Core**: Clean separation between business logic and HTTP concerns
2. **Standard Library First**: Handlers implement `net/http.Handler` interface
3. **Clean Separation**: Business logic separate from HTTP delivery
4. **Extensible**: Database adapters, plugins, and services
5. **Production-Ready**: Thread-safe, secure, and performant

---

## 🔌 Plugin System

Create custom plugins to extend the library with additional business logic:

```go
package main

import (
    "context"
    "github.com/m-t-a97/go-better-auth/plugin"
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

func (p *CustomPlugin) OnUserSignUp(ctx context.Context, userID string) error {
    // Custom logic when user signs up
    // e.g., send welcome email, create profile, etc.
    return nil
}

func (p *CustomPlugin) OnUserSignIn(ctx context.Context, userID string) error {
    // Custom logic when user signs in
    // e.g., log activity, update last login, etc.
    return nil
}

func (p *CustomPlugin) OnOAuthSuccess(ctx context.Context, userID, provider string) error {
    // Custom logic after successful OAuth
    return nil
}
```

Plugins are instantiated and passed to the Go Better Auth config during initialization.

---

## 💾 Database Adapters

### SQLite

```go
Database: gobetterauth.DatabaseConfig{
    Provider:         "sqlite",
    ConnectionString: "/path/to/database.db", // or ":memory:" for in-memory
}
```

### PostgreSQL

```go
Database: gobetterauth.DatabaseConfig{
    Provider:         "postgres",
    ConnectionString: "postgres://user:password@localhost/dbname?sslmode=disable",
}
```

**Schema Migration:**

You can find the files in `migrations/` folder.

---

### CSRF Protection

Automatic CSRF token validation for state-changing operations.

---

## 🌟 Examples

See the `examples/` directory for complete examples:

- Basic email/password authentication
- OAuth integration
- Custom plugin development
- Multi-provider setup

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Follow Go best practices and conventions
2. Maintain clean architecture principles
3. Add tests for new features
4. Update documentation

---

## 📄 License

MIT License - see LICENSE file for details

---

## 📞 Support

- GitHub Issues: [Report bugs or request features](https://github.com/m-t-a97/go-better-auth/issues)
- Documentation: [Full documentation](https://github.com/m-t-a97/go-better-auth/wiki)

---
