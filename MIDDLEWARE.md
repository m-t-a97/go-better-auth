# Middleware Documentation

This package provides reusable HTTP middleware for authentication and session management. The middleware is framework-agnostic and works with any framework that supports `http.Handler` or `http.HandlerFunc`.

## Overview

The middleware package provides:

1. **AuthMiddleware** - Required authentication middleware that validates session tokens and extracts user IDs
2. **OptionalAuthMiddleware** - Optional authentication middleware that gracefully handles missing tokens
3. **Context utilities** - Helper functions for getting/setting values in request context

## Quick Start

### Basic Usage with net/http

```go
package main

import (
	"net/http"
	"github.com/m-t-a97/go-better-auth/middleware"
	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

func main() {
	service := setupAuthService() // Your auth service
	authMiddleware := middleware.NewAuthMiddleware(service)

	// Protect an endpoint
	http.Handle("/api/protected", authMiddleware.Handler(
		http.HandlerFunc(protectedHandler),
	))

	http.ListenAndServe(":8080", http.DefaultServeMux)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Use userID to fetch user data
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello, " + userID))
}
```

## Middleware Types

### AuthMiddleware

Requires valid authentication. Returns 401 Unauthorized if no valid token is present.

#### Creation

```go
// Default (uses "session" cookie name)
authMiddleware := middleware.NewAuthMiddleware(service)

// Custom cookie name
authMiddleware := middleware.NewAuthMiddlewareWithCookie(service, "auth_token")
```

#### Usage

```go
// With Handler
mux.Handle("/api/protected", authMiddleware.Handler(
	http.HandlerFunc(yourHandler),
))

// With HandlerFunc
mux.HandleFunc("/api/protected", authMiddleware.HandlerFunc(yourHandler))
```

#### Token Sources

Tokens are extracted in this order:
1. `Authorization: Bearer <token>` header
2. Cookie (default: `session`, or custom name)

```bash
# Bearer token
curl -H "Authorization: Bearer your-token-here" http://localhost:8080/api/protected

# Cookie
curl -b "session=your-token-here" http://localhost:8080/api/protected
```

### OptionalAuthMiddleware

Optional authentication. Allows requests without tokens to pass through.

#### Creation

```go
// Default
optionalAuth := middleware.NewOptionalAuthMiddleware(service)

// Custom cookie name
optionalAuth := middleware.NewOptionalAuthMiddlewareWithCookie(service, "auth_token")
```

#### Usage

```go
mux.Handle("/api/public", optionalAuth.Handler(
	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated
		userID, err := middleware.GetUserID(r.Context())
		if err != nil {
			// Not authenticated
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("public access"))
			return
		}

		// Authenticated
		w.Write([]byte("Hello, " + userID))
	}),
))
```

## Context Utilities

### Getting Values

```go
import "github.com/m-t-a97/go-better-auth/middleware"

// Get user ID
userID, err := middleware.GetUserID(r.Context())
if err != nil {
	// Handle error - user ID not found in context
}

// Get session token
token, err := middleware.GetSessionToken(r.Context())
if err != nil {
	// Handle error - token not found in context
}

// Must get (panics if not found)
userID := middleware.MustGetUserID(r.Context())
```

### Setting Values

```go
// Manually set user ID in context
ctx := middleware.SetUserID(r.Context(), "user-123")

// Manually set session token in context
ctx = middleware.SetSessionToken(ctx, "token-123")

// Use updated context
newReq := r.WithContext(ctx)
```

## Framework Integration

### net/http (standard library)

```go
authMiddleware := middleware.NewAuthMiddleware(service)

// Option 1: Handle method
http.Handle("/api/users", authMiddleware.Handler(
	http.HandlerFunc(usersHandler),
))

// Option 2: HandleFunc with middleware
http.HandleFunc("/api/profile", authMiddleware.HandlerFunc(
	profileHandler,
))
```

### gorilla/mux

```go
import "github.com/gorilla/mux"

router := mux.NewRouter()
authMiddleware := middleware.NewAuthMiddleware(service)

// Protect a route
router.Handle("/api/protected", authMiddleware.Handler(
	http.HandlerFunc(protectedHandler),
))

// Or with chain
router.Handle("/api/protected", 
	authMiddleware.Handler(
		otherMiddleware(
			http.HandlerFunc(protectedHandler),
		),
	),
)
```

### chi

```go
import "github.com/go-chi/chi"

router := chi.NewRouter()
authMiddleware := middleware.NewAuthMiddleware(service)

// Protected route
router.Group(func(r chi.Router) {
	r.Use(func(next http.Handler) http.Handler {
		return authMiddleware.Handler(next)
	})

	r.Get("/api/protected", protectedHandler)
})
```

### echo

```go
import "github.com/labstack/echo/v4"

e := echo.New()
authMiddleware := middleware.NewAuthMiddleware(service)

// Adapt middleware
e.Use(echo.WrapMiddleware(func(next http.Handler) http.Handler {
	return authMiddleware.Handler(next)
}))

// Or per route
e.GET("/api/protected", echo.WrapHandler(
	authMiddleware.Handler(http.HandlerFunc(protectedHandler)),
))
```

## Error Handling

### AuthMiddleware Errors

```go
authMiddleware := middleware.NewAuthMiddleware(service)

handler := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// If we reach here, authentication succeeded
	userID := middleware.MustGetUserID(r.Context())
	w.Write([]byte("User: " + userID))
}))

// If authentication fails:
// - 401 Unauthorized response is sent
// - Handler is NOT called
```

### OptionalAuthMiddleware Behavior

```go
optionalAuth := middleware.NewOptionalAuthMiddleware(service)

handler := optionalAuth.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Handler is ALWAYS called
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		// No user ID - request passed without auth
		w.Write([]byte("public"))
		return
	}

	// Has user ID - request was authenticated
	w.Write([]byte("user: " + userID))
}))
```

## Advanced Usage

### Custom Cookie Name

```go
// Use a different cookie name
authMiddleware := middleware.NewAuthMiddlewareWithCookie(
	service,
	"my_auth_token",
)
```

### Middleware Composition

```go
// Chain multiple middlewares
loggingMiddleware := func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

authMiddleware := middleware.NewAuthMiddleware(service)

handler := loggingMiddleware(
	authMiddleware.Handler(
		http.HandlerFunc(protectedHandler),
	),
)

http.Handle("/api/protected", handler)
```

### Protected and Public Routes

```go
authMiddleware := middleware.NewAuthMiddleware(service)
optionalAuth := middleware.NewOptionalAuthMiddleware(service)

mux := http.NewServeMux()

// Protected routes
mux.Handle("/api/protected", authMiddleware.Handler(
	http.HandlerFunc(protectedHandler),
))

// Public routes with optional auth
mux.Handle("/api/public", optionalAuth.Handler(
	http.HandlerFunc(publicHandler),
))

// Public routes with no auth
mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})
```

### User Context Access

```go
// In your handler, access user information
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Safely get user ID
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Get session token if needed
	token, _ := middleware.GetSessionToken(r.Context())

	// Use the values
	fmt.Printf("User %s authenticated with token %s\n", userID, token)
}
```

## Testing

Example test for middleware:

```go
func TestProtectedEndpoint(t *testing.T) {
	service := setupAuthService()
	middleware := middleware.NewAuthMiddleware(service)

	// Create authenticated request
	token := "valid-session-token"
	req := httptest.NewRequest("GET", "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer " + token)

	// Create handler
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := middleware.GetUserID(r.Context())
		w.Write([]byte(userID))
	}))

	// Test
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "expected-user-id", w.Body.String())
}
```

## Security Considerations

1. **Always use HTTPS in production** - Session tokens are credentials
2. **Set secure cookie flags** - Use Secure and HttpOnly flags
3. **Token validation** - Middleware validates token format and expiration
4. **Logout implementation** - Delete session from repository on logout
5. **Token refresh** - Implement token refresh to limit exposure

## Performance

- Middleware has minimal overhead
- Session validation is performed per-request
- Context operations are O(1)
- No allocation for middleware operation itself

## See Also

- [Authentication Examples](./examples/middleware_usage.go)
- [Middleware Tests](./middleware/auth_test.go)
- [Context Package](./middleware/context.go)
