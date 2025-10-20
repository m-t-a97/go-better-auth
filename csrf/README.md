# CSRF Protection Package

A production-ready Cross-Site Request Forgery (CSRF) protection implementation for Go using the double-submit cookie pattern.

## Quick Start

### Installation

```bash
go get github.com/m-t-a97/go-better-auth/csrf
```

### Basic Usage

```go
package main

import (
	"time"
	"github.com/m-t-a97/go-better-auth/csrf"
)

func main() {
	// Create repository (in-memory for development)
	repo := csrf.NewInMemoryRepository()

	// Create manager
	manager := csrf.NewManager(repo, 15*time.Minute, false)

	// Generate token
	token, secret, _ := manager.GenerateToken()

	// Use token and secret for CSRF protection
	// Token -> sent to client (in header or form)
	// Secret -> stored in HTTP-only cookie (set automatically by middleware)
}
```

## Features

✅ **Double-Submit Cookie Pattern** - Industry-standard CSRF protection  
✅ **Framework Agnostic** - Works with any Go HTTP framework (Chi, Gin, Echo, etc.)  
✅ **Multiple Storage Backends** - In-memory and PostgreSQL repositories included  
✅ **Token Expiration** - Automatic cleanup of expired tokens  
✅ **One-Time Use** - Tokens are deleted after validation  
✅ **Comprehensive Logging** - Easy debugging and security monitoring  
✅ **Test-Friendly** - Easy to test CSRF protection with helper functions  
✅ **Production Ready** - Secure defaults and best practices built-in  

## How It Works

### The Double-Submit Cookie Pattern

1. **Client requests a form** (GET request)
   - Server generates random token and secret
   - Stores secret in HTTP-only cookie
   - Sends token in response

2. **Client submits form** (POST/PUT/DELETE request)
   - Includes token in header or form field
   - Browser automatically includes cookie with secret

3. **Server validates**
   - Verifies token exists and isn't expired
   - Checks secret in cookie matches stored secret
   - Deletes token (one-time use)
   - Allows request if valid, rejects with 403 if invalid

### Why It's Secure

- ✅ Token and secret are independent - attacker can't forge both
- ✅ HttpOnly flag prevents JavaScript access to secret
- ✅ SameSite attribute prevents browser from sending cookie cross-site
- ✅ One-time use prevents token replay attacks
- ✅ Expiration prevents indefinite token validity
- ✅ No server-side session state required (stateless)

## Repository Options

### InMemoryRepository

```go
repo := csrf.NewInMemoryRepository()
```

**Best for:**
- Development and testing
- Single-instance deployments
- CI/CD pipelines

**Limitations:**
- Tokens lost on restart
- Not suitable for production
- Doesn't scale across multiple servers

### PostgresRepository

```go
db, _ := sql.Open("postgres", connectionString)
repo := csrf.NewPostgresRepository(db)
repo.InitSchema(ctx) // Run once
```

**Best for:**
- Production deployments
- Multi-server setups
- Persistent token storage

**Features:**
- Automatic expiration handling
- Scales across multiple servers
- Persistent storage
- Efficient cleanup

## Configuration

### Token Time-To-Live (TTL)

```go
// Very short TTL (high security)
manager := csrf.NewManager(repo, 5*time.Minute, true)

// Default TTL (balanced)
manager := csrf.NewManager(repo, 15*time.Minute, true)

// Long TTL (better UX)
manager := csrf.NewManager(repo, 1*time.Hour, true)
```

### Secure Flag

```go
// HTTPS in production
manager := csrf.NewManager(repo, 15*time.Minute, true)

// HTTP in development
manager := csrf.NewManager(repo, 15*time.Minute, false)
```

## Integration Examples

### With Chi Framework

```go
import "github.com/go-chi/chi/v5"

repo := csrf.NewInMemoryRepository()
manager := csrf.NewManager(repo, 15*time.Minute, false)
middleware := csrf.NewMiddleware(manager)

r := chi.NewRouter()
r.Use(middleware.Handler)

// Routes are now CSRF protected
r.Post("/api/action", handler)
```

### With Gin Framework

```go
import "github.com/gin-gonic/gin"

repo := csrf.NewInMemoryRepository()
manager := csrf.NewManager(repo, 15*time.Minute, false)
middleware := csrf.NewMiddleware(manager)

r := gin.Default()
r.Use(func(c *gin.Context) {
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Request = r
	})).ServeHTTP(c.Writer, c.Request)
})
```

### HTML Form (Server-Rendered)

```html
<form method="POST" action="/api/auth/sign-up">
	<!-- Include CSRF token -->
	<input type="hidden" name="_csrf" value="{{ .CSRFToken }}">
	
	<!-- Rest of form -->
	<input type="email" name="email" required>
	<button type="submit">Sign Up</button>
</form>

<script>
	// Get fresh token on page load
	fetch('/api/auth/session')
		.then(res => {
			const token = res.headers.get('X-CSRF-Token');
			document.querySelector('input[name="_csrf"]').value = token;
		});
</script>
```

### JavaScript/SPA

```javascript
// On page load, fetch CSRF token
const csrfToken = sessionStorage.getItem('csrfToken');

// Make request with CSRF token
fetch('/api/auth/sign-up', {
	method: 'POST',
	headers: {
		'Content-Type': 'application/json',
		'X-CSRF-Token': csrfToken,
	},
	credentials: 'include', // Include cookies
	body: JSON.stringify({
		email: 'user@example.com',
		password: 'password123'
	})
})
```

## API Reference

### Manager Methods

```go
// Generate new CSRF token pair
token, secret, err := manager.GenerateToken()

// Validate token against secret
isValid, err := manager.ValidateToken(token, secret)

// Set CSRF secret cookie on response
manager.SetCSRFCookie(w, secret)

// Get CSRF secret from request
secret, err := manager.GetCSRFCookie(r)

// Cleanup expired tokens
err := manager.CleanupExpiredTokens()
```

### Middleware Methods

```go
// Create CSRF middleware
middleware := csrf.NewMiddleware(manager)

// Wrap HTTP handler
handler = middleware.Handler(handler)

// Wrap HTTP handler function
handlerFunc = middleware.HandlerFunc(handlerFunc)

// Manual validation
err := middleware.ValidateRequest(w, r)

// Generate token for response
token, err := middleware.GenerateTokenForResponse(w)
```

### Helper Functions

```go
// Get CSRF token from request (header or form)
token, err := csrf.GetCSRFToken(r)

// Generate HTML hidden input field
html := csrf.HiddenInput(token)

// Generate HTML meta tag
html := csrf.HTMLMetaTag(token)

// Create template-ready token
tmplToken := csrf.NewTemplateToken(token)
```

### Constants

```go
const (
	CSRFTokenLength    = 32                           // bytes
	CSRFSecretLength   = 32                           // bytes
	CSRFCookieName     = "_csrf_secret"               // cookie name
	CSRFHeaderName     = "X-CSRF-Token"               // header name
	CSRFFormField      = "_csrf"                      // form field name
)
```

## Testing

```go
func TestCSRFProtection(t *testing.T) {
	// Create test repository
	repo := csrf.NewInMemoryRepository()
	manager := csrf.NewManager(repo, 15*time.Minute, false)

	// Generate token
	token, secret, _ := manager.GenerateToken()

	// Create test request
	req := httptest.NewRequest("POST", "/api/action", nil)
	req.Header.Set(csrf.CSRFHeaderName, token)
	req.AddCookie(&http.Cookie{
		Name:  csrf.CSRFCookieName,
		Value: secret,
	})

	// Validate
	isValid, _ := manager.ValidateToken(token, secret)
	if !isValid {
		t.Fatal("Token validation failed")
	}
}
```

## Security Best Practices

1. **Always use HTTPS in production** - Ensures secure cookie transmission
2. **Set secure flag to true** - Prevents cookies from being sent over HTTP
3. **Use HttpOnly cookies** - Protects against XSS attacks
4. **Generate fresh tokens** - On every GET request for forms
5. **Implement token cleanup** - Run periodically to manage storage
6. **Monitor CSRF failures** - Detect and log potential attacks
7. **Use SameSite attribute** - Browser-level CSRF protection
8. **Validate both directions** - Check token in POST and secret in cookie

## Error Handling

```go
const (
	ErrCSRFTokenMissing  = "CSRF token is missing"
	ErrCSRFSecretMissing = "CSRF secret cookie is missing"
	ErrCSRFTokenInvalid  = "CSRF token is invalid or expired"
	ErrCSRFMismatch      = "CSRF token does not match the secret"
)
```

## Performance Considerations

### Memory Usage

- **InMemoryRepository**: ~1KB per token
- **PostgresRepository**: Minimal memory, uses database

### Token Generation

- Cryptographically secure random generation
- ~0.1ms per token
- Suitable for high-traffic applications

### Cleanup Strategy

```go
// Run cleanup periodically
go func() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		manager.CleanupExpiredTokens()
	}
}()
```

## Troubleshooting

### Tokens Expiring Too Quickly

- **Problem**: Users get CSRF errors on slow form submissions
- **Solution**: Increase TTL

```go
manager := csrf.NewManager(repo, 1*time.Hour, true)
```

### Missing Token Errors

- **Problem**: Token not being sent in request
- **Solution**: Verify token is included in header or form

```javascript
// Check header is set
fetch(url, {
	headers: {
		'X-CSRF-Token': token,
	}
})

// Or check form field is included
<input type="hidden" name="_csrf" value="{{ .Token }}">
```

### Cookie Not Set

- **Problem**: Browser not accepting CSRF secret cookie
- **Solution**: Check SameSite and Secure flags

```go
// For HTTPS (production)
manager := csrf.NewManager(repo, 15*time.Minute, true)

// For HTTP (development)
manager := csrf.NewManager(repo, 15*time.Minute, false)
```

## Related Documentation

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Double-Submit Cookie Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie)
- [SameSite Cookies Explained](https://web.dev/samesite-cookies-explained/)

## License

MIT License - See LICENSE file for details
