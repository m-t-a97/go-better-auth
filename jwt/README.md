# JWT Package

The JWT package provides RS256-based JSON Web Token (JWT) management for the go-better-auth library. It supports creating, verifying, and refreshing tokens with configurable expiration times.

## Features

- **RS256 Signing**: Uses RSA private/public key pairs for secure token signing
- **Token Pair Management**: Creates both access and refresh tokens
- **Token Verification**: Validates token signatures and claims
- **Token Refresh**: Create new access tokens from refresh tokens
- **Expiration Handling**: Built-in support for token expiration checks
- **OAuth Integration**: Special support for OAuth token flows with provider information

## Usage

### Initialize Manager

```go
import "github.com/m-t-a97/go-better-auth/jwt"

// Create a new manager with auto-generated RSA keys
manager, err := jwt.NewManager("https://example.com", []string{"https://example.com"})
if err != nil {
    log.Fatal(err)
}

// Export keys for storage/reuse
privateKey, publicKey, err := manager.ExportKeys()
```

### Create Tokens

```go
// Create a token pair (access + refresh)
tokenPair, err := manager.CreateTokenPair(
    userID,                // "user123"
    email,                 // "user@example.com"
    name,                  // "John Doe"
    15 * time.Minute,      // access token expiry
    7 * 24 * time.Hour,    // refresh token expiry
)
if err != nil {
    log.Fatal(err)
}

fmt.Println("Access Token:", tokenPair.AccessToken)
fmt.Println("Refresh Token:", tokenPair.RefreshToken)
fmt.Println("Expires In:", tokenPair.ExpiresIn, "seconds")
```

### Verify Tokens

```go
// Verify and extract claims
claims, err := manager.VerifyToken(tokenString)
if err != nil {
    log.Fatal(err)
}

fmt.Println("User ID:", claims.UserID)
fmt.Println("Email:", claims.Email)
fmt.Println("Name:", claims.Name)
```

### Refresh Tokens

```go
// Create a new access token from a refresh token
newAccessToken, err := manager.RefreshAccessToken(
    refreshTokenString,
    15 * time.Minute, // new token expiry
)
if err != nil {
    log.Fatal(err)
}
```

### Check Token Status

```go
// Check if token is expired
isExpired := manager.IsTokenExpired(tokenString)

// Get remaining time before expiration
remaining := manager.GetRemainingTime(tokenString)
fmt.Printf("Token expires in: %v\n", remaining)
```

### OAuth Tokens

```go
// Create OAuth-specific token pairs with provider info
tokenPair, err := manager.CreateOAuthTokenPair(
    userID,                  // "user123"
    email,                   // "user@example.com"
    name,                    // "John Doe"
    "google",                // provider
    "oauth-account-id",      // OAuth account ID
    15 * time.Minute,        // access token expiry
    7 * 24 * time.Hour,      // refresh token expiry
)
```

## Token Structure

Tokens include standard JWT claims:

- `sub` (subject): User ID
- `email`: User email
- `name`: User name
- `iat` (issued at): Token creation time
- `exp` (expiration): Token expiration time
- `iss` (issuer): Token issuer
- `aud` (audience): Token audience
- `provider` (OAuth only): OAuth provider name
- `account_id` (OAuth only): OAuth account ID

## Security Considerations

1. **Key Management**: Store RSA private keys securely. Never expose them in client-side code.
2. **HTTPS Only**: Always transmit tokens over HTTPS.
3. **Token Storage**: Store tokens in secure, HttpOnly cookies or secure storage (not localStorage).
4. **Expiration Times**: Keep access tokens short-lived (15 minutes recommended) and refresh tokens longer-lived (7 days typical).
5. **Key Rotation**: Implement key rotation policies for security.

## Integration with Better Auth

The JWT package integrates seamlessly with better auth's OAuth and session management:

```go
// Use JWT tokens instead of opaque session tokens
tokenPair, err := jwtManager.CreateOAuthTokenPair(
    user.ID, user.Email, user.Name, provider, accountID,
    15 * time.Minute, 7 * 24 * time.Hour,
)
```

Then, on subsequent requests, verify the token:

```go
claims, err := jwtManager.VerifyToken(tokenString)
if err != nil {
    // Token invalid or expired
    return err
}
// Use claims.UserID to identify the user
```
