# Session Authentication Middleware

Framework-agnostic session authentication middleware for Go Better Auth. This middleware validates session tokens from cookies and populates the request context with authenticated user information.

## Features

- ✅ Framework-agnostic (works with Chi, Echo, Gin, standard `net/http`, etc.)
- ✅ Cookie-based session management
- ✅ Automatic session validation and expiration checking
- ✅ Context-based user/session storage
- ✅ Optional authentication mode for public endpoints
- ✅ Secure cookie settings (HttpOnly, Secure, SameSite)
- ✅ Simple and composable API

## Installation

```bash
go get github.com/m-t-a97/go-better-auth
```

## Quick Start

### Basic Usage

```go
package main

import (
    "net/http"
    "github.com/m-t-a97/go-better-auth/sessionauth"
    "github.com/m-t-a97/go-better-auth/domain"
)

func main() {
    // Initialize repositories (using your adapter of choice)
    var sessionRepo domain.SessionRepository
    var userRepo domain.UserRepository

    // Create session manager
    manager := sessionauth.NewManager(sessionRepo, userRepo, &sessionauth.ManagerConfig{
        Secure: true, // Set to true in production with HTTPS
    })

    // Create middleware
    authMiddleware := sessionauth.NewMiddleware(manager)

    // Protect routes
    http.Handle("/protected", authMiddleware.Handler(http.HandlerFunc(protectedHandler)))
    http.ListenAndServe(":8080", nil)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    // Get authenticated user from context
    user := sessionauth.GetUser(r)
    session := sessionauth.GetSession(r)

    // User is guaranteed to be authenticated here
    w.Write([]byte("Hello, " + user.Name))
}
```

## Configuration

### Manager Configuration

```go
config := &sessionauth.ManagerConfig{
    CookieName: "_session",  // Custom cookie name (default: "_session")
    Secure:     true,        // Enable secure flag for HTTPS
    Path:       "/",         // Cookie path (default: "/")
}

manager := sessionauth.NewManager(sessionRepo, userRepo, config)
```

## Middleware Types

### Required Authentication

Blocks requests without valid sessions:

```go
middleware := sessionauth.NewMiddleware(manager)
```

### Optional Authentication

Allows requests through but populates context if valid session exists:

```go
middleware := sessionauth.NewOptionalMiddleware(manager)

// In handler
user := sessionauth.GetUser(r)
if user != nil {
    // User is authenticated
} else {
    // Anonymous request
}
```

## Framework Examples

### Standard `net/http`

```go
mux := http.NewServeMux()

// Public route
mux.HandleFunc("/public", publicHandler)

// Protected route
mux.Handle("/api/profile", authMiddleware.Handler(http.HandlerFunc(profileHandler)))

http.ListenAndServe(":8080", mux)
```

### Chi Router

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()

// Public routes
r.Get("/", homeHandler)

// Protected routes group
r.Group(func(r chi.Router) {
    r.Use(authMiddleware.Handler)
    
    r.Get("/profile", profileHandler)
    r.Post("/settings", settingsHandler)
})

http.ListenAndServe(":8080", r)
```

### Echo Framework

```go
import "github.com/labstack/echo/v4"

e := echo.New()

// Convert to Echo middleware
echoAuth := echo.WrapMiddleware(authMiddleware.Handler)

// Public route
e.GET("/", homeHandler)

// Protected routes
protectedGroup := e.Group("/api")
protectedGroup.Use(echoAuth)
protectedGroup.GET("/profile", profileHandler)
protectedGroup.POST("/settings", settingsHandler)

e.Start(":8080")
```

### Gin Framework

```go
import "github.com/gin-gonic/gin"

r := gin.Default()

// Convert to Gin middleware
ginAuth := func(c *gin.Context) {
    authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        c.Request = r
        c.Next()
    })).ServeHTTP(c.Writer, c.Request)
}

// Public route
r.GET("/", homeHandler)

// Protected routes
authorized := r.Group("/api")
authorized.Use(ginAuth)
{
    authorized.GET("/profile", profileHandler)
    authorized.POST("/settings", settingsHandler)
}

r.Run(":8080")
```

## Accessing Session & User Data

### Safe Access (Returns nil if not present)

```go
func handler(w http.ResponseWriter, r *http.Request) {
    user := sessionauth.GetUser(r)
    if user == nil {
        // No authenticated user
        return
    }
    
    session := sessionauth.GetSession(r)
    // Use user and session...
}
```

### Must Access (Panics if not present)

Use only in handlers protected by required authentication:

```go
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    // This will panic if middleware isn't applied - good for catching bugs early
    user := sessionauth.MustGetUser(r)
    session := sessionauth.MustGetSession(r)
    
    // User is guaranteed to exist here
}
```

## Complete Example with Login/Logout

```go
package main

import (
    "encoding/json"
    "net/http"
    "time"
    
    "github.com/m-t-a97/go-better-auth/sessionauth"
    "github.com/m-t-a97/go-better-auth/usecase"
)

func main() {
    // Setup (repositories, use cases, etc.)
    var authUseCase *usecase.AuthUseCase
    var sessionRepo domain.SessionRepository
    var userRepo domain.UserRepository
    
    manager := sessionauth.NewManager(sessionRepo, userRepo, &sessionauth.ManagerConfig{
        Secure: true,
    })
    
    authMiddleware := sessionauth.NewMiddleware(manager)
    
    // Routes
    http.HandleFunc("/login", loginHandler(authUseCase, manager))
    http.HandleFunc("/logout", logoutHandler(manager))
    http.Handle("/profile", authMiddleware.Handler(http.HandlerFunc(profileHandler)))
    
    http.ListenAndServe(":8080", nil)
}

func loginHandler(authUseCase *usecase.AuthUseCase, manager *sessionauth.Manager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var input usecase.SignInEmailInput
        if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }
        
        // Authenticate user
        output, err := authUseCase.SignInEmail(r.Context(), input)
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }
        
        // Set session cookie
        manager.SetSessionCookie(w, output.Session.Token, output.Session.ExpiresAt)
        
        json.NewEncoder(w).Encode(map[string]any{
            "user": output.User,
        })
    }
}

func logoutHandler(manager *sessionauth.Manager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Clear session cookie
        manager.ClearSessionCookie(w)
        
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{
            "message": "Logged out successfully",
        })
    }
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    user := sessionauth.MustGetUser(r)
    
    json.NewEncoder(w).Encode(map[string]any{
        "user": user,
    })
}
```

## Security Considerations

### Production Settings

```go
config := &sessionauth.ManagerConfig{
    Secure: true,  // MUST be true in production (requires HTTPS)
}
```

### Cookie Security

The middleware automatically sets:
- `HttpOnly: true` - Prevents JavaScript access to cookies
- `SameSite: Lax` - CSRF protection
- `Secure: true` (when configured) - HTTPS only

### Session Expiration

Sessions are automatically validated for expiration. Expired sessions:
1. Return 401 Unauthorized
2. Are deleted from the database
3. Have their cookie cleared

## Context Keys

The middleware stores data in the request context using these keys:

- `"session"` - The validated session (`*domain.Session`)
- `"user"` - The authenticated user (`*domain.User`)

## Error Handling

The middleware handles these scenarios:

| Scenario | Required Auth | Optional Auth |
|----------|--------------|---------------|
| No cookie | 401 Unauthorized | Continue (no context) |
| Invalid token | 401 Unauthorized | Continue (no context) |
| Expired session | 401 Unauthorized | Continue (no context) |
| Valid session | Add to context → Continue | Add to context → Continue |

## Testing

Run the test suite:

```bash
go test ./sessionauth/...
```

## License

See the main project LICENSE file.
