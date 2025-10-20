# Session Auth Middleware - Quick Start Guide

## What Was Implemented

A **framework-agnostic session authentication middleware** for go-better-auth that uses only Go's standard library `http.Handler` interface. It works with any Go web framework.

## Core Components

### 1. Middleware Package (`sessionauth/`)

**Main files:**
- `middleware.go` - Core middleware implementation
- `context.go` - Context helpers for accessing user/session
- `middleware_test.go` - 19 unit tests (all passing ✅)
- `README.md` - Full documentation
- `adapters.go` - Framework integration guide

### 2. Integration Point

Added to `client.go` - Quick access:
```go
auth, _ := gobetterauth.New(config)
middleware := auth.SessionAuth()
```

## Basic Usage

### Standard Library (Most Direct)
```go
package main

import (
    "net/http"
    gobetterauth "github.com/m-t-a97/go-better-auth"
    "github.com/m-t-a97/go-better-auth/sessionauth"
)

func main() {
    auth, _ := gobetterauth.New(config)
    middleware := auth.SessionAuth()
    
    mux := http.NewServeMux()
    
    // Optional auth - user info attached if valid session
    mux.Handle("/", middleware.Handler(publicHandler))
    
    // Required auth - returns 401 if not authenticated
    mux.Handle("/api/user", middleware.Require(protectedHandler))
    
    http.ListenAndServe(":3000", mux)
}

func publicHandler(w http.ResponseWriter, r *http.Request) {
    user := sessionauth.GetUser(r.Context())
    if user != nil {
        w.Write([]byte("Hello " + user.Name))
    } else {
        w.Write([]byte("Hello Guest"))
    }
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    user := sessionauth.GetUser(r.Context())
    // user is guaranteed to be non-nil here
    w.Write([]byte("Hello " + user.Name))
}
```

### Chi Router
```go
package main

import (
    "github.com/go-chi/chi/v5"
    gobetterauth "github.com/m-t-a97/go-better-auth"
)

func main() {
    auth, _ := gobetterauth.New(config)
    middleware := auth.SessionAuth()
    
    router := chi.NewRouter()
    
    // Optional auth for all routes
    router.Use(middleware.Handler)
    
    // Public route
    router.Get("/", publicHandler)
    
    // Protected route
    router.Post("/api/user", middleware.Require(protectedHandler))
    
    http.ListenAndServe(":3000", router)
}
```

## Key Methods

### Middleware Methods

| Method | Behavior | Use Case |
|--------|----------|----------|
| `Handler(next http.Handler)` | Attaches user if valid session exists, continues if not | Optional auth |
| `Require(next http.Handler)` | Returns 401 if no valid session | Protected routes |
| `HandlerFunc(next http.HandlerFunc)` | Optional auth wrapper for handler funcs | Alternative syntax |
| `RequireFunc(next http.HandlerFunc)` | Required auth wrapper for handler funcs | Alternative syntax |
| `WithCookieName(name)` | Configure session cookie name | Custom cookie names |

### Context Helpers

```go
// Get authenticated user (nil if not authenticated)
user := sessionauth.GetUser(r.Context())

// Get session object
session := sessionauth.GetSession(r.Context())

// Check if authenticated
if sessionauth.IsAuthenticated(r.Context()) {
    // User is authenticated
}

// Get user ID (empty string if not authenticated)
userID := sessionauth.GetUserID(r.Context())
```

## Session Token Sources

The middleware automatically tries these in order:

1. **Authorization Header**: `Authorization: Bearer <token>`
2. **Cookie**: Cookie named `go-better-auth.session` (configurable)

## Testing

All 19 tests pass:
```bash
$ go test ./sessionauth -v
# Output: 19 tests PASSED ✅
```

## Features

✅ Framework-agnostic (uses only `http.Handler`)  
✅ Two authentication modes (optional & required)  
✅ Multiple token sources (Bearer & cookie)  
✅ Context-based user/session access  
✅ Custom cookie name support  
✅ Automatic session expiration handling  
✅ Comprehensive test coverage  
✅ Production-ready error handling  

## Common Patterns

### Conditional Handler Behavior
```go
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if sessionauth.IsAuthenticated(r.Context()) {
        // User is authenticated
        user := sessionauth.GetUser(r.Context())
        w.Write([]byte("Hello " + user.Name))
    } else {
        // User not authenticated
        http.Error(w, "Please sign in", http.StatusUnauthorized)
    }
})

// Use optional auth - always continues
router.Get("/api/data", middleware.Handler(handler))
```

### Protecting Multiple Routes
```go
// Method 1: Individual protection
router.Post("/api/user", middleware.Require(updateUserHandler))
router.Put("/api/user", middleware.Require(updateUserHandler))
router.Delete("/api/user", middleware.Require(deleteUserHandler))

// Method 2: Protected subrouter
protected := chi.NewRouter()
protected.Use(middleware.Require)
protected.Post("/user", updateUserHandler)
protected.Put("/user", updateUserHandler)
protected.Delete("/user", deleteUserHandler)
router.Mount("/api", protected)
```

### Custom Cookie Names
```go
middleware := auth.SessionAuth().
    WithCookieName("my-app-session")
```

## Documentation

For detailed documentation, examples, and security considerations, see:
- `sessionauth/README.md` - Full API reference and framework integration
- `SESSIONAUTH_IMPLEMENTATION.md` - Implementation details
