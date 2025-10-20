# Go Better Auth Framework Integration Examples

This directory contains complete working examples of how to integrate Go Better Auth with different Go web frameworks.

## Examples

### Chi Integration (`chi_integration.go`)

The simplest integration since Chi works directly with `http.HandlerFunc`.

```bash
go run examples/chi_integration.go
```

**Features:**
- Minimal wrapper code
- Direct handler registration
- Native middleware support

### Echo Integration (`echo_integration.go`)

Demonstrates integration with the Echo framework.

```bash
go run examples/echo_integration.go
```

**Features:**
- Handler wrapping pattern
- Protected route groups
- Custom middleware integration

### Gin Integration (`gin_integration.go`)

Shows how to use Go Better Auth with Gin.

```bash
go run examples/gin_integration.go
```

**Features:**
- Gin-specific handler wrapping
- Route groups
- Custom middleware

### Fiber Integration (`fiber_integration.go`)

Demonstrates integration with the Fiber framework.

```bash
go run examples/fiber_integration.go
```

**Features:**
- Fiber adaptor middleware wrapping
- Protected route groups
- High-performance framework integration

## Common Pattern

All examples follow the same pattern:

1. **Initialize Go Better Auth**
   ```go
   auth, err := gobetterauth.New(config)
   if err != nil {
       log.Fatal(err)
   }
   ```

2. **Get Handlers and Middleware**
   ```go
   handlers := auth.GetHandlers()
   middlewares := auth.GetMiddleware()
   ```

3. **Register Routes**
   - Public routes (no auth required)
   - Protected routes (with SessionAuth middleware)
   - OAuth routes

4. **Start Server**
   ```go
   http.ListenAndServe(":8080", router)
   ```

## Adding New Frameworks

To integrate Go Better Auth with a new framework:

1. Create a new file `<framework>_integration.go`
2. Create a setup function that:
   - Creates a router/engine
   - Gets handlers and middleware via `auth.GetHandlers()` and `auth.GetMiddleware()`
   - Wraps handlers if needed (depends on framework)
   - Registers routes
   - Returns the configured router

Example template:

```go
package examples

import (
    "github.com/yourframework/v1"
    "github.com/m-t-a97/go-better-auth/pkg/gobetterauth"
)

func SetupYourFrameworkServer(auth *gobetterauth.GoBetterAuth) *yourframework.Engine {
    engine := yourframework.New()
    
    handlers := auth.GetHandlers()
    middlewares := auth.GetMiddleware()
    
    // Register routes...
    
    return engine
}
```

## Testing Integration

Each example includes commented-out `main()` functions for testing:

1. Uncomment the `main()` function
2. Configure database connection in the Config
3. Run: `go run examples/<framework>_integration.go`
4. Test endpoints with curl or Postman

Example:
```bash
# Sign up
curl -X POST http://localhost:8080/api/auth/sign-up/email \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password","name":"User"}'

# Sign in
curl -X POST http://localhost:8080/api/auth/sign-in/email \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'
```

## Framework Compatibility

| Framework | Status | Complexity | Notes |
|-----------|--------|-----------|-------|
| Chi | ✅ Recommended | Low | Direct http.HandlerFunc support |
| Echo | ✅ Supported | Medium | Requires handler wrapping |
| Gin | ✅ Supported | Medium | Requires handler wrapping |
| Fiber | ✅ Supported | Medium | Uses adaptor middleware |
| Gorilla Mux | ✅ Supported | Low | Works like Chi |
| Standard Library | ✅ Supported | Low | Direct registration |

## Need Help?

- Check the main [FRAMEWORK_INTEGRATION.md](../docs/FRAMEWORK_INTEGRATION.md) for detailed documentation
- Review the commented main() functions in each example
- Check the Go Better Auth README for configuration options
      <input name="email" type="email" placeholder="Email" required />
      <input name="password" type="password" placeholder="Password" required />
      <button type="submit">Sign In</button>
      <button onClick={() => window.location.href = 'http://localhost:3000/api/auth/oauth/google'}>
        Sign in with Google
      </button>
    </form>
  );
}
```
