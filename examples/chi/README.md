# Chi Router Example

This example demonstrates how to use go-better-auth with the **Chi** HTTP router.

## Overview

Go Better Auth provides a complete, built-in HTTP handler that implements all authentication endpoints. This example shows how to simply mount the auth handler with your Chi router.

### Key Architecture

```
Your Chi Router
    ↓
router.Mount("/api/auth", auth.Handler())
    ↓
Go Better Auth Handler
    ├── All auth endpoints
    ├── Session management
    ├── OAuth handling
    └── Email verification
    ↓
Database Layer (SQLite/PostgreSQL)
```

## Getting Started

### 1. Initialize Go Better Auth

```go
auth, err := gobetterauth.New(&gobetterauth.Config{
    Database: gobetterauth.DatabaseConfig{
        Provider:         "sqlite",
        ConnectionString: ":memory:",
    },
    BaseURL: "http://localhost:3000",
    EmailAndPassword: gobetterauth.EmailPasswordConfig{
        Enabled:    true,
        AutoSignIn: true,
    },
})
if err != nil {
    log.Fatalf("Failed to initialize: %v", err)
}
```

### 2. Create Your Router and Mount the Auth Handler

```go
router := chi.NewRouter()
router.Use(middleware.Logger)
router.Use(middleware.Recoverer)

// Mount all auth endpoints
router.Mount("/api/auth", auth.Handler())
```

### 3. Available Endpoints

All endpoints are automatically available after mounting:

- `POST /api/auth/sign-up/email` - Sign up with email/password
- `POST /api/auth/sign-in/email` - Sign in with email/password
- `POST /api/auth/sign-out` - Sign out and invalidate session
- `GET /api/auth/session` - Get current session
- `POST /api/auth/send-verification-email` - Send email verification
- `POST /api/auth/verify-email` - Verify email token
- `POST /api/auth/request-password-reset` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/change-password` - Change password (authenticated)
- `GET /api/auth/oauth/{provider}` - OAuth sign-in redirect
- And more...

## Running the Example

```bash
cd examples/chi
go run main.go
```

The server starts on `http://localhost:3000`. Try:

```bash
curl -X POST http://localhost:3000/api/auth/sign-up/email \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!"}'
```

## Understanding the Code

### main.go

The complete example showing:
- How to initialize go-better-auth
- How to create a Chi router
- How to mount the auth handler
- How to add your own application routes

The approach is intentionally simple - go-better-auth provides all the HTTP handling, so you just need to mount it!

## Customization

### Add Application Routes

```go
router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status":"ok"}`))
})

router.Get("/protected", requireAuth(func(w http.ResponseWriter, r *http.Request) {
    // Your protected route logic
}))
```

### Add Custom Middleware

```go
router.Use(middleware.Logger)
router.Use(middleware.Recoverer)
router.Use(middleware.Heartbeat("/ping"))

// Mount auth handler with middleware applied before it
router.Mount("/api/auth", auth.Handler())
```

### Use with PostgreSQL

Simply change the database config:

```go
auth, err := gobetterauth.New(&gobetterauth.Config{
    Database: gobetterauth.DatabaseConfig{
        Provider:         "postgres",
        ConnectionString: "postgres://user:pass@localhost:5432/authdb",
    },
    // ... rest of config
})
```

## Key Points

1. **Minimal Setup** - Mount the handler, get all auth features
2. **Framework Agnostic** - Go Better Auth works with any Go HTTP framework
3. **Production Ready** - Full session management, secure cookies, CSRF protection
4. **Extensible** - Add your own routes and middleware as needed
5. **Multiple Databases** - SQLite, PostgreSQL, or extensible to others

## See Also

- [Echo Example](../echo/README.md) - Same functionality with Echo router
- [Go Better Auth Documentation](https://github.com/m-t-a97/go-better-auth) - Full library documentation
- [Chi Documentation](https://github.com/go-chi/chi) - Chi router docs
