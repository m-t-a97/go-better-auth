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
go get github.com/better-auth/go-better-auth
```

### Basic Usage

```go
package main

import (
    "log"
    "net/http"
    "time"
    
    "github.com/better-auth/go-better-auth/pkg/betterauth"
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
config := &betterauth.Config{
    EmailAndPassword: betterauth.EmailPasswordConfig{
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
SocialProviders: betterauth.SocialProvidersConfig{
    Google: &betterauth.GoogleProviderConfig{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:3000/api/auth/oauth/google/callback",
    },
    GitHub: &betterauth.GitHubProviderConfig{
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
EmailAndPassword: betterauth.EmailPasswordConfig{
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
EmailAndPassword: betterauth.EmailPasswordConfig{
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
    ├── betterauth/          # Main library interface
    │   └── betterauth.go
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
   - BetterAuth configuration and builder
   - Plugin system interface

## 🔌 Plugin System

Create custom plugins to extend functionality:

```go
package main

import (
    "net/http"
    "github.com/better-auth/go-better-auth/pkg/plugin"
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
Database: betterauth.DatabaseConfig{
    Provider:         "postgres",
    ConnectionString: "postgres://user:password@localhost/dbname?sslmode=disable",
}
```

**Schema Migration:**

```sql
CREATE TABLE users (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    image TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    token VARCHAR(512) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE accounts (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    id_token TEXT,
    access_token_expires_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    scope TEXT,
    password TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(provider_id, account_id)
);

CREATE TABLE verifications (
    id VARCHAR(255) PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    value VARCHAR(512) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);
```

### Custom Database Adapter

Implement the repository interfaces:

```go
type CustomUserRepository struct {
    // Your implementation
}

func (r *CustomUserRepository) Create(ctx context.Context, user *domain.User) error {
    // Implementation
}

// Implement other methods...
```

## 🔒 Security Features

### Password Hashing

Uses **scrypt** by default (OWASP recommended):

```go
Advanced: betterauth.AdvancedConfig{
    PasswordHasher: usecase.NewScryptPasswordHasher(),
}
```

### Custom Password Hasher

```go
type CustomHasher struct{}

func (h *CustomHasher) Hash(password string) (string, error) {
    // Custom hashing logic
}

func (h *CustomHasher) Verify(password, hash string) bool {
    // Custom verification logic
}

config.Advanced.PasswordHasher = &CustomHasher{}
```

### Secure Cookies

```go
Advanced: betterauth.AdvancedConfig{
    SecureCookies: true,  // HTTPS only
    TrustedOrigins: []string{"https://yourdomain.com"},
}
```

### CSRF Protection

Automatic CSRF token validation for state-changing operations.

## 📖 API Reference

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/sign-up/email` | Register new user |
| POST | `/api/auth/sign-in/email` | Sign in with email |
| POST | `/api/auth/sign-out` | Sign out current session |
| GET | `/api/auth/session` | Get current session |
| POST | `/api/auth/send-verification-email` | Send verification email |
| GET | `/api/auth/verify-email` | Verify email address |
| POST | `/api/auth/request-password-reset` | Request password reset |
| POST | `/api/auth/reset-password` | Reset password with token |
| POST | `/api/auth/change-password` | Change password (authenticated) |

### OAuth Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/oauth/{provider}` | Initiate OAuth flow |
| GET | `/api/auth/oauth/{provider}/callback` | OAuth callback handler |

### Request/Response Examples

**Sign Up:**
```json
POST /api/auth/sign-up/email
{
  "email": "user@example.com",
  "password": "secure123",
  "name": "John Doe",
  "image": "https://example.com/avatar.jpg"
}

Response:
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "emailVerified": false
  },
  "session": {
    "id": "session-uuid",
    "token": "session-token",
    "expiresAt": "2024-01-01T00:00:00Z"
  }
}
```

## 🧪 Testing

```go
package main_test

import (
    "testing"
    "github.com/better-auth/go-better-auth/pkg/betterauth"
)

func TestAuth(t *testing.T) {
    config := &betterauth.Config{
        Database: betterauth.DatabaseConfig{
            Provider:         "sqlite",
            ConnectionString: ":memory:",
        },
    }
    
    auth, err := betterauth.New(config)
    if err != nil {
        t.Fatal(err)
    }
    
    // Test authentication flows
}
```

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

## 🙏 Acknowledgments

Inspired by [Better Auth](https://better-auth.com) - The TypeScript authentication framework

## 📞 Support

- GitHub Issues: [Report bugs or request features](https://github.com/better-auth/go-better-auth/issues)
- Documentation: [Full documentation](https://github.com/better-auth/go-better-auth/wiki)

---

Built with ❤️ using Go and Clean Architecture principles
