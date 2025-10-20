# Go Better Auth 🔐

A comprehensive, framework-agnostic authentication and authorization library for Go, inspired by [Better Auth](https://better-auth.com). Built with clean architecture principles, SOLID design patterns, and Go best practices.

## ✨ Features

- 🔑 **Email & Password Authentication** - Built-in support with secure password hashing (scrypt)
- 🌐 **Social OAuth Providers** - Google, GitHub, Discord, and extensible generic OAuth2 support
- 🔐 **Session Management** - Secure session handling with customizable expiration
- ✉️ **Email Verification** - Optional email verification workflow
- 🔄 **Password Reset** - Secure password reset functionality
- 🏗️ **Clean Architecture** - Separation of concerns with domain, usecase, delivery, and infrastructure layers
- 🔌 **Plugin System** - Extensible architecture for adding custom functionality
- 💾 **Multiple Database Support** - PostgreSQL, MySQL, SQLite (via adapters)
- 🛡️ **Security First** - CSRF protection, secure cookies, rate limiting support
- 📦 **Zero Dependencies** - Minimal external dependencies, production-ready

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

## 📚 Core Concepts

### Authentication Methods

#### Email & Password

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
