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

### Basic Usage - Two Approaches

Go Better Auth can be used in two ways:

#### Option 1: Standalone Framework (Simplest)

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
        BaseURL: "http://localhost:3000",
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
    
    log.Fatal(http.ListenAndServe(":3000", nil))
}
```

#### Option 2: Custom HTTP Handlers (Maximum Control)

Extract use cases and implement custom HTTP handlers with your chosen framework:

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/go-chi/chi/v5"
    "github.com/m-t-a97/go-better-auth"
)

func main() {
    config := &gobetterauth.Config{
        BaseURL: "http://localhost:3000",
        Database: gobetterauth.DatabaseConfig{
            Provider:         "sqlite",
            ConnectionString: ":memory:",
        },
    }
    
    auth, err := gobetterauth.New(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Get use cases and implement custom handlers
    authUseCase := auth.AuthUseCase()
    
    router := chi.NewRouter()
    router.Post("/api/auth/sign-up", func(w http.ResponseWriter, r *http.Request) {
        // Custom implementation
    })
    
    log.Fatal(http.ListenAndServe(":3000", router))
}
```

**Choose Option 1 for simplicity, or Option 2 for flexibility with your preferred framework (chi, gin, echo, fiber, etc.).**

### Detailed Setup and Initialization

Go Better Auth is initialized via the `gobetterauth.New(config)` function, which takes a `Config` struct. The library provides **both**:

1. **Built-in HTTP Handlers**: Use `auth.Handler()` to get an `http.Handler` that implements all authentication endpoints
2. **Use Cases & Repositories**: Extract use cases with `auth.AuthUseCase()` and implement custom handlers

**Architecture Overview:**
```
Option 1: Standalone         Option 2: Custom Handlers
┌─────────────────────────┐ ┌──────────────────────────────┐
│ Your Application        │ │ Your Application              │
│ (any HTTP server)       │ │ (chi, gin, echo, fiber, etc.) │
└────────────┬────────────┘ └──────────────┬─────────────────┘
             │ mounts                       │ uses
             │                              │
       ┌─────▼──────────┐         ┌────────▼──────────┐
       │ auth.Handler() │         │ Use Cases (API)   │
       │ (http.Handler) │         │ • AuthUseCase     │
       └─────┬──────────┘         │ • OAuthUseCase    │
             │                    └────────┬──────────┘
             ▼                             │
       ┌──────────────────┐         ┌─────▼──────────────┐
       │ Domain Layer     │         │ Custom Handlers    │
       │ Repositories     │         │ (Your Framework)   │
       │ Use Cases        │         └─────┬──────────────┘
       │ Services         │               │
       └─────┬────────────┘               ▼
             │               ┌──────────────────────┐
             └──────┬────────►│ Domain Layer        │
                    │         │ Repositories        │
                    │         │ Use Cases           │
                    │         │ Services            │
                    │         └──────────────────────┘
                    │
            ┌───────▼────────────┐
            │ Database Adapters  │
            │ (PostgreSQL, etc)  │
            └────────────────────┘
```

**Setup Steps:**

1. **Configuration**: Populate the `Config` struct with your settings. Required: `BaseURL`, `Database`
2. **Database Setup**: Run migrations from `migrations/` folder
3. **Email Integration**: Provide callbacks for email sending
4. **Session Configuration**: Customize expiration in `SessionConfig`
5. **OAuth Setup**: Configure provider credentials and redirect URLs
6. **Initialization**: Call `gobetterauth.New(config)`
7. **Choose your approach**:
   - **Option 1**: Use `auth.Handler()` for built-in handlers
   - **Option 2**: Use `auth.AuthUseCase()` for custom implementation
8. **Deploy**: The library is thread-safe and production-ready

## 📚 Core Concepts

### How the Library Works

Go Better Auth provides both **standalone HTTP handlers** and **use cases** for your custom implementation. Choose the approach that fits your needs:

**Approach 1: Standalone (Built-in Handlers)**
- Use `auth.Handler()` to get a complete `http.Handler` implementing all auth endpoints
- Works with the standard library `net/http` package
- Minimal setup required
- Perfect for small to medium projects

**Approach 2: Custom Implementation (Use Cases)**
- Extract use cases with `auth.AuthUseCase()`, `auth.OAuthUseCase()`, etc.
- Implement your own HTTP handlers with your preferred framework (chi, gin, echo, fiber, etc.)
- Maximum flexibility and control
- Perfect for large projects with custom requirements

**Core Features:**
- **Authentication Flow**: Email/password signup and signin with optional email verification
- **OAuth Support**: Automatic OAuth flow handling for Google, GitHub, Discord, and generic providers
- **Session Management**: Secure session creation, validation, and refresh
- **Security**: Password hashing (scrypt), CSRF protection, secure cookies
- **Extensibility**: Use cases and repositories are fully customizable
- **Database**: Multiple database support via adapters (PostgreSQL, SQLite)

#### Authentication Methods

##### Email & Password

Call the use case from your HTTP handler:

```go
authUseCase := auth.AuthUseCase()

// Sign up
output, err := authUseCase.SignUpEmail(ctx, &usecase.SignUpEmailInput{
    Email:    "user@example.com",
    Password: "secure123",
})

// Sign in
output, err := authUseCase.SignInEmail(ctx, &usecase.SignInEmailInput{
    Email:    "user@example.com",
    Password: "secure123",
})
```

**Example HTTP Handler (chi):**
```go
router.Post("/api/auth/sign-up/email", func(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    json.NewDecoder(r.Body).Decode(&req)
    
    // Call use case
    output, err := authUseCase.SignUpEmail(r.Context(), &usecase.SignUpEmailInput{
        Email:    req.Email,
        Password: req.Password,
    })
    
    // Return response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(output)
})
```

#### OAuth Social Providers

Supported providers:
- **Google** - OpenID Connect
- **GitHub** - OAuth 2.0
- **Discord** - OAuth 2.0
- **Generic OAuth2** - Extensible for any provider

Call the use case from your HTTP handler:

```go
oauthUseCase := auth.OAuthUseCase()

// Get authorization URL
authURL, err := oauthUseCase.GetAuthURL(
    "google",                                          // provider
    "state-token",                                      // CSRF protection
    "http://localhost:3000/api/auth/oauth/google/callback",
)

// Handle callback
output, err := oauthUseCase.Authenticate(ctx, &usecase.OAuthAuthenticateInput{
    Provider: "google",
    Code:     "auth-code",
    State:    "state-token",
})

// Refresh tokens
refreshOutput, err := oauthUseCase.RefreshToken(ctx, &usecase.RefreshTokenInput{
    UserID:   user.ID,
    Provider: "google",
})
```

**Example HTTP Handler (chi):**
```go
// Initiate OAuth flow
router.Get("/api/auth/oauth/{provider}", func(w http.ResponseWriter, r *http.Request) {
    provider := chi.URLParam(r, "provider")
    authURL, _ := oauthUseCase.GetAuthURL(provider, "state", "callback")
    http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
})

// Handle OAuth callback
router.Get("/api/auth/oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    
    output, _ := oauthUseCase.Authenticate(r.Context(), &usecase.OAuthAuthenticateInput{
        Provider: chi.URLParam(r, "provider"),
        Code:     code,
        State:    state,
    })
    
    json.NewEncoder(w).Encode(output)
})
```

### Session Management

Call the use case to manage sessions:

```go
authUseCase := auth.AuthUseCase()

// Get current session
session, user, err := authUseCase.GetSession(ctx, token)
if err != nil {
    // Handle error (session expired, invalid token, etc.)
}

// Sign out (invalidate session)
err = authUseCase.SignOut(ctx, token)

// Refresh session
output, err := authUseCase.RefreshSession(ctx, &usecase.RefreshSessionInput{
    Token: sessionToken,
})
```

**Example HTTP Handler (chi):**
```go
router.Get("/api/auth/session", func(w http.ResponseWriter, r *http.Request) {
    // Get session from cookie or header
    token := r.Header.Get("Authorization")
    
    session, user, err := authUseCase.GetSession(r.Context(), token)
    if err != nil {
        http.Error(w, "Invalid session", http.StatusUnauthorized)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "user":    user,
        "session": session,
    })
})

router.Post("/api/auth/sign-out", func(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    authUseCase.SignOut(r.Context(), token)
    w.WriteHeader(http.StatusOK)
})
```

### Email Verification

Enable email verification in config and implement the email sending callback:

```go
config := &gobetterauth.Config{
    EmailAndPassword: gobetterauth.EmailPasswordConfig{
        RequireEmailVerification: true,
        SendVerificationEmail: func(email, token, url string) error {
            // Send verification email to user
            return sendEmail(email, "Verify your email", url)
        },
    },
}
```

Then implement HTTP handlers to call the use cases:

```go
authUseCase := auth.AuthUseCase()

// Send verification email
router.Post("/api/auth/send-verification-email", func(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email string `json:"email"`
    }
    json.NewDecoder(r.Body).Decode(&req)
    
    err := authUseCase.SendVerificationEmail(r.Context(), &usecase.SendVerificationEmailInput{
        Email: req.Email,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusOK)
})

// Verify email
router.Get("/api/auth/verify-email", func(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    
    output, err := authUseCase.VerifyEmail(r.Context(), &usecase.VerifyEmailInput{
        Token: token,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(output)
})
```

### Password Reset

Enable password reset in config:

```go
config := &gobetterauth.Config{
    EmailAndPassword: gobetterauth.EmailPasswordConfig{
        SendPasswordResetEmail: func(email, token, url string) error {
            // Send password reset email to user
            return sendEmail(email, "Reset your password", url)
        },
    },
}
```

Implement HTTP handlers to call the use cases:

```go
authUseCase := auth.AuthUseCase()

// Request password reset
router.Post("/api/auth/request-password-reset", func(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email string `json:"email"`
    }
    json.NewDecoder(r.Body).Decode(&req)
    
    err := authUseCase.RequestPasswordReset(r.Context(), &usecase.RequestPasswordResetInput{
        Email: req.Email,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusOK)
})

// Reset password
router.Post("/api/auth/reset-password", func(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Token       string `json:"token"`
        NewPassword string `json:"newPassword"`
    }
    json.NewDecoder(r.Body).Decode(&req)
    
    err := authUseCase.ResetPassword(r.Context(), &usecase.ResetPasswordInput{
        Token:       req.Token,
        NewPassword: req.NewPassword,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusOK)
})

// Change password (requires authentication)
router.Post("/api/auth/change-password", func(w http.ResponseWriter, r *http.Request) {
    var req struct {
        CurrentPassword    string `json:"currentPassword"`
        NewPassword        string `json:"newPassword"`
        RevokeOtherSessions bool  `json:"revokeOtherSessions"`
    }
    json.NewDecoder(r.Body).Decode(&req)
    
    token := r.Header.Get("Authorization") // Get session token
    
    err := authUseCase.ChangePassword(r.Context(), &usecase.ChangePasswordInput{
        Token:               token,
        CurrentPassword:     req.CurrentPassword,
        NewPassword:         req.NewPassword,
        RevokeOtherSessions: req.RevokeOtherSessions,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusOK)
})
```

## ⚡ Rate Limiting

Go Better Auth provides a rate limiting middleware that you can apply to your HTTP handlers to prevent abuse on authentication endpoints.

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

3. Get the rate limiting middleware from the library and apply to your routes:

```go
import "github.com/m-t-a97/go-better-auth/ratelimit"

// Get repositories to pass to rate limiting middleware
repos := auth.Repositories()

// Create rate limiting middleware
rateLimitMiddleware := ratelimit.NewMiddleware(&ratelimit.Config{
    Enabled:     true,
    RedisURL:    "redis://localhost:6379",
    MaxRequests: 10,
    Window:      1 * time.Minute,
})

// Apply to your routes
router.Post("/api/auth/sign-up/email", rateLimitMiddleware.Handler(handleSignUpEmail))
router.Post("/api/auth/sign-in/email", rateLimitMiddleware.Handler(handleSignInEmail))
router.Get("/api/auth/oauth/{provider}", rateLimitMiddleware.Handler(handleOAuthCallback))
```

Exceeded rate limits return HTTP 429 (Too Many Requests).

**Example:**
```go
func handleSignUpEmail(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    json.NewDecoder(r.Body).Decode(&req)
    
    output, err := authUseCase.SignUpEmail(r.Context(), &usecase.SignUpEmailInput{
        Email:    req.Email,
        Password: req.Password,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(output)
}

// Apply rate limiting to the handler
router.Post("/api/auth/sign-up/email", rateLimitMiddleware.Handler(handleSignUpEmail))
```

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

2. Get the MFA use case and implement HTTP handlers:

```go
mfaUseCase := auth.MFAUseCase()

// Enable MFA
router.Post("/api/auth/enable-mfa", func(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization") // Session token
    
    output, err := mfaUseCase.EnableMFA(r.Context(), &usecase.EnableMFAInput{
        Token: token,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "secret":     output.Secret,
        "qrCodeURL":  output.QRCodeURL,
    })
})

// Verify MFA during login
router.Post("/api/auth/verify-mfa", func(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Code string `json:"code"`
        // Other sign-in fields...
    }
    json.NewDecoder(r.Body).Decode(&req)
    
    output, err := mfaUseCase.VerifyMFA(r.Context(), &usecase.VerifyMFAInput{
        Code: req.Code,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(output)
})

// Disable MFA
router.Post("/api/auth/disable-mfa", func(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    
    err := mfaUseCase.DisableMFA(r.Context(), &usecase.DisableMFAInput{
        Token: token,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.WriteHeader(http.StatusOK)
})
```

## 🔄 Token Refresh & Management

Go Better Auth provides comprehensive token refresh functionality for both OAuth and session tokens.

### OAuth Token Refresh

Call the use case to refresh OAuth access tokens:

```go
oauthUseCase := auth.OAuthUseCase()

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

**Example HTTP Handler (chi):**
```go
router.Post("/api/auth/oauth/{provider}/refresh", func(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    
    // Get user from session
    session, user, _ := authUseCase.GetSession(r.Context(), token)
    
    // Refresh OAuth tokens
    output, err := oauthUseCase.RefreshToken(r.Context(), &usecase.RefreshTokenInput{
        UserID:   user.ID,
        Provider: chi.URLParam(r, "provider"),
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "accessToken":  output.AccessToken,
        "refreshToken": output.RefreshToken,
        "idToken":      output.IDToken,
        "expiresIn":    output.ExpiresIn,
    })
})
```

### Session Refresh

Extend session expiration:

```go
authUseCase := auth.AuthUseCase()

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

**Example HTTP Handler (chi):**
```go
router.Post("/api/auth/session/refresh", func(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    
    output, err := authUseCase.RefreshSession(r.Context(), &usecase.RefreshSessionInput{
        Token: token,
    })
    
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "user":    output.User,
        "session": output.Session,
    })
})
```

### Clean Expired Sessions

Automatically clean up expired sessions:

```go
authUseCase := auth.AuthUseCase()

// Clean expired sessions from database
err := authUseCase.CleanExpiredSessions(ctx)
```

Run this periodically (e.g., via cron job) to maintain database performance.

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

## 🏗️ Architecture

Go Better Auth follows **Clean Architecture** principles with a dual-mode design:

```
┌────────────────────────────────────────────────────┐
│          Go Better Auth Library                    │
├────────────────────────────────────────────────────┤
│  Mode 1: Standalone HTTP Handlers                  │
│  • Built-in http.Handler implementation            │
│  • auth.Handler() returns ready-to-use handler     │
│  • Mount on any standard HTTP server               │
├────────────────────────────────────────────────────┤
│  Mode 2: Custom Use Cases                          │
│  • auth.AuthUseCase() - authentication logic       │
│  • auth.OAuthUseCase() - OAuth handling            │
│  • Implement handlers with your framework          │
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

1. **Dual-Mode**: Both standalone handlers AND use cases available
2. **Framework-Agnostic Core**: Use cases work with any framework  
3. **Standard Library First**: Handlers implement `net/http.Handler` interface
4. **Clean Separation**: Business logic separate from HTTP concerns
5. **Extensible**: Database adapters, custom handlers, plugins

**Choose Your Mode:**
- **Standalone** (`auth.Handler()`): Use built-in handlers for quick projects
- **Custom** (`auth.AuthUseCase()`): Implement handlers with your preferred framework (chi, gin, echo, fiber, etc.)

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
