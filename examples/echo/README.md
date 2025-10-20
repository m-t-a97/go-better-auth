# Echo Router Example

This example demonstrates how to use go-better-auth with the **Echo** HTTP router.

## Overview

Go Better Auth provides a complete, built-in HTTP handler that implements all authentication endpoints. This example shows how to simply mount the auth handler with your Echo router.

### Key Architecture

```
Your Echo Router
    ↓
router.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))
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
router := echo.New()
router.Use(middleware.Logger())
router.Use(middleware.Recover())
router.Use(middleware.CORSWithConfig(middleware.CORSConfig{
    AllowOrigins: []string{"*"},
    AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
}))

// Mount all auth endpoints using WrapHandler to adapt http.Handler to Echo
router.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))
router.Any("/api/auth", echo.WrapHandler(auth.Handler()))
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
cd examples/echo
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
- How to create an Echo router
- How to mount the auth handler using `echo.WrapHandler()`
- How to add your own application routes
- How to configure CORS and other middleware

The approach is intentionally simple - go-better-auth provides all the HTTP handling, so you just need to mount it!

## Customization

### Add Application Routes

```go
router.GET("/health", func(c echo.Context) error {
    return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
})

router.POST("/api/users", func(c echo.Context) error {
    // Your protected route logic
    return c.JSON(http.StatusCreated, map[string]string{"message": "user created"})
})
```

### Add Custom Middleware

```go
router.Use(middleware.Logger())
router.Use(middleware.Recover())
router.Use(middleware.CORSWithConfig(middleware.CORSConfig{
    AllowOrigins: []string{"http://localhost:3000", "http://localhost:5173"},
    AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
}))

// Mount auth handler with middleware applied before it
router.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))
router.Any("/api/auth", echo.WrapHandler(auth.Handler()))
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

## Echo vs Chi: Key Differences

| Feature | Chi | Echo |
|---------|-----|------|
| Handler Mounting | `router.Mount()` | `router.Any()` with `echo.WrapHandler()` |
| Response Binding | `json.NewEncoder()` | `c.JSON()`, `c.String()`, etc. |
| Middleware | `router.Use()` | `router.Use()` |
| Route Grouping | `r.Route()` | `g := router.Group()` |
| Context | `*http.Request` | `echo.Context` |

Both provide similar functionality; the examples here show both patterns for flexibility.

## Key Points

1. **Minimal Setup** - Mount the handler, get all auth features
2. **Framework Agnostic** - Go Better Auth works with any Go HTTP framework
3. **Production Ready** - Full session management, secure cookies, CSRF protection
4. **Extensible** - Add your own routes and middleware as needed
5. **Multiple Databases** - SQLite, PostgreSQL, or extensible to others

## See Also

- [Chi Example](../chi/README.md) - Same functionality with Chi router
- [Go Better Auth Documentation](https://github.com/m-t-a97/go-better-auth) - Full library documentation
- [Echo Documentation](https://echo.labstack.com/) - Echo router docs
