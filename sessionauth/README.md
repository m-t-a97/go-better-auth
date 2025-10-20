# Session Auth Middleware

A framework-agnostic session authentication middleware for protecting routes in your Go application. This middleware validates session tokens from cookies or Authorization headers and attaches authenticated user information to the request context.

## Features

- 🔒 **Framework Agnostic** - Works with any framework that supports `http.Handler` (Chi, Echo, Gin, standard library, etc.)
- 🍪 **Cookie & Bearer Token Support** - Automatically extracts sessions from cookies or `Authorization: Bearer` headers
- 📋 **Context Injection** - Attaches user and session data to request context for easy access
- 🛡️ **Flexible Authentication** - Optional authentication middleware (continues request) and required authentication middleware (returns 401)
- 🧪 **Testable** - Clean interfaces and context helpers for easy testing

## Installation

```bash
go get github.com/m-t-a97/go-better-auth
```

## Quick Start

### Basic Usage - Optional Authentication

```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/m-t-a97/go-better-auth/sessionauth"
)

func main() {
    router := chi.NewRouter()
    
    // Create session auth middleware
    authMiddleware := sessionauth.NewMiddleware(sessionRepo, userRepo)
    
    // Optionally wrap all routes (user info will be attached if authenticated)
    router.Use(authMiddleware.Handler)
    
    // Handler can check if user is authenticated
    router.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
        user := sessionauth.GetUser(r.Context())
        if user == nil {
            http.Error(w, "Not authenticated", http.StatusUnauthorized)
            return
        }
        
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"user":"` + user.Email + `"}`))
    })
    
    http.ListenAndServe(":3000", router)
}
```

### Required Authentication

```go
// Middleware that returns 401 if user is not authenticated
router.Post("/api/user/settings", authMiddleware.Require(
    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := sessionauth.GetUser(r.Context())
        // user is guaranteed to be non-nil here
        updateUserSettings(w, user.ID)
    }),
))
```

### With Helper Functions

```go
package main

import (
    "github.com/m-t-a97/go-better-auth/sessionauth"
    "github.com/go-chi/chi/v5"
)

func main() {
    router := chi.NewRouter()
    
    // Use convenience functions
    router.Use(sessionauth.OptionalAuth(sessionRepo, userRepo))
    
    // Protected routes
    router.Post("/api/protected", sessionauth.AuthenticatedOnly(sessionRepo, userRepo)(
        protectedHandler,
    ))
}
```

## API Reference

### Middleware Creation

#### `NewMiddleware(sessionRepo, userRepo) *Middleware`
Creates a new session authentication middleware.

```go
middleware := sessionauth.NewMiddleware(sessionRepo, userRepo)
```

#### `WithCookieName(name) *Middleware`
Sets a custom cookie name (default: "go-better-auth.session").

```go
middleware := sessionauth.NewMiddleware(sessionRepo, userRepo).
    WithCookieName("my-session")
```

### Middleware Functions

#### `Handler(next http.Handler) http.Handler`
Optional authentication - attaches user info if session is valid, continues request even if not authenticated.

```go
router.Use(middleware.Handler)
```

#### `Require(next http.Handler) http.Handler`
Required authentication - returns 401 if user is not authenticated.

```go
router.Post("/api/protected", middleware.Require(handler))
```

#### `HandlerFunc(next http.HandlerFunc) http.HandlerFunc`
Wrapper for handler functions with optional authentication.

```go
http.HandleFunc("/optional", middleware.HandlerFunc(handler))
```

#### `RequireFunc(next http.HandlerFunc) http.HandlerFunc`
Wrapper for handler functions with required authentication.

```go
http.HandleFunc("/protected", middleware.RequireFunc(handler))
```

### Context Helpers

#### `GetUser(ctx) *domain.User`
Retrieves the authenticated user from context. Returns nil if not authenticated.

```go
user := sessionauth.GetUser(r.Context())
if user != nil {
    fmt.Println(user.Email)
}
```

#### `GetSession(ctx) *domain.Session`
Retrieves the current session from context. Returns nil if no session.

```go
session := sessionauth.GetSession(r.Context())
if session != nil {
    fmt.Println(session.ExpiresAt)
}
```

#### `IsAuthenticated(ctx) bool`
Checks if a user is authenticated.

```go
if sessionauth.IsAuthenticated(r.Context()) {
    // User is authenticated
}
```

#### `GetUserID(ctx) string`
Gets the authenticated user's ID. Returns empty string if not authenticated.

```go
userID := sessionauth.GetUserID(r.Context())
```

### Convenience Functions

#### `OptionalAuth(sessionRepo, userRepo) func(http.Handler) http.Handler`
Creates optional auth middleware (permissive - continues even if not authenticated).

```go
router.Use(sessionauth.OptionalAuth(sessionRepo, userRepo))
```

#### `AuthenticatedOnly(sessionRepo, userRepo) func(http.Handler) http.Handler`
Creates required auth middleware (returns 401 if not authenticated).

```go
router.Post("/api/protected", sessionauth.AuthenticatedOnly(sessionRepo, userRepo)(handler))
```

## Framework Examples

### Chi Router

```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
    gobetterauth "github.com/m-t-a97/go-better-auth"
    "github.com/m-t-a97/go-better-auth/sessionauth"
)

func main() {
    auth, _ := gobetterauth.New(config)
    
    router := chi.NewRouter()
    router.Mount("/api/auth", auth.Handler())
    
    // Optional auth for all routes
    authMiddleware := sessionauth.NewMiddleware(auth.SessionRepo(), auth.UserRepo())
    router.Use(authMiddleware.Handler)
    
    // Public route
    router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Public"))
    })
    
    // Protected route
    router.Post("/api/user", authMiddleware.Require(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := sessionauth.GetUser(r.Context())
            w.Write([]byte("Hello " + user.Name))
        }),
    ))
    
    http.ListenAndServe(":3000", router)
}
```

### Echo Framework

```go
package main

import (
    "net/http"
    "github.com/labstack/echo/v4"
    gobetterauth "github.com/m-t-a97/go-better-auth"
    "github.com/m-t-a97/go-better-auth/sessionauth"
)

func main() {
    auth, _ := gobetterauth.New(config)
    e := echo.New()
    
    // Mount auth handler
    e.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))
    
    // Create middleware
    middleware := sessionauth.NewMiddleware(auth.SessionRepo(), auth.UserRepo())
    
    // Optional auth middleware
    e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                // Update context
                c.SetRequest(r)
                next(c)
            })).ServeHTTP(c.Response(), c.Request())
            return nil
        }
    })
    
    // Protected route
    e.POST("/api/user", func(c echo.Context) error {
        user := sessionauth.GetUser(c.Request().Context())
        if user == nil {
            return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
        }
        return c.JSON(http.StatusOK, user)
    })
    
    e.Start(":3000")
}
```

### Standard Library

```go
package main

import (
    "net/http"
    gobetterauth "github.com/m-t-a97/go-better-auth"
    "github.com/m-t-a97/go-better-auth/sessionauth"
)

func main() {
    auth, _ := gobetterauth.New(config)
    
    mux := http.NewServeMux()
    
    // Mount auth
    mux.Handle("/api/auth/", auth.Handler())
    
    // Create middleware
    authMiddleware := sessionauth.NewMiddleware(auth.SessionRepo(), auth.UserRepo())
    
    // Public route
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Public"))
    })
    
    // Protected route
    mux.Handle("/api/user", authMiddleware.Require(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := sessionauth.GetUser(r.Context())
            w.Write([]byte("Hello " + user.Name))
        }),
    ))
    
    http.ListenAndServe(":3000", mux)
}
```

## Session Token Extraction

The middleware automatically extracts session tokens in this order:

1. **Authorization Header**: `Authorization: Bearer <token>`
2. **Cookie**: Cookie with name from `m.cookieName` (default: "go-better-auth.session")

You can customize the cookie name:

```go
middleware := sessionauth.NewMiddleware(sessionRepo, userRepo).
    WithCookieName("custom-session-name")
```

## Error Handling

The middleware handles the following scenarios:

| Scenario | Optional Auth | Required Auth |
|----------|---------------|---------------|
| Valid session | User attached | User attached |
| No token found | Continue (no user) | Return 401 |
| Invalid session | Continue (no user) | Return 401 |
| Expired session | Continue (no user) | Return 401 |
| User not found | Continue (no user) | Return 401 |

When using optional authentication, you can check if a user is authenticated:

```go
if sessionauth.IsAuthenticated(r.Context()) {
    // User is authenticated
} else {
    // No user or invalid session
}
```

## Testing

Here's an example of testing a handler with session auth:

```go
package main

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
    
    "github.com/m-t-a97/go-better-auth/domain"
    "github.com/m-t-a97/go-better-auth/sessionauth"
)

func TestProtectedHandler(t *testing.T) {
    // Create test user and context
    user := &domain.User{
        ID:    "123",
        Name:  "Test User",
        Email: "test@example.com",
    }
    ctx := context.WithValue(context.Background(), "sessionauth:user", user)
    
    // Create request with context
    req := httptest.NewRequest("GET", "/api/user", nil).WithContext(ctx)
    w := httptest.NewRecorder()
    
    // Test handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := sessionauth.GetUser(r.Context())
        if user == nil {
            http.Error(w, "Not authenticated", http.StatusUnauthorized)
            return
        }
        w.Write([]byte(user.Email))
    })
    
    handler.ServeHTTP(w, req)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected 200, got %d", w.Code)
    }
}
```

## Security Considerations

1. **HTTPS Only** - Always use HTTPS in production. Configure cookies with `Secure` flag.
2. **SameSite Policy** - Session cookies should have `SameSite=Strict` or `SameSite=Lax`.
3. **CSRF Protection** - Use CSRF middleware from `go-better-auth/csrf` for state-changing requests.
4. **Session Expiration** - Sessions automatically expire based on configured duration.
5. **Rate Limiting** - Consider using rate limiting middleware from `go-better-auth/ratelimit`.

## License

MIT
