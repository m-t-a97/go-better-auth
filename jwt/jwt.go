package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	jwtpkg "github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT claims
type Claims struct {
	UserID    string `json:"sub"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Provider  string `json:"provider,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	jwtpkg.RegisteredClaims
}

// Manager handles JWT token creation and verification
type Manager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   []string
}

// TokenPair contains access and refresh tokens
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

// NewManager creates a new JWT manager with RSA keys
func NewManager(issuer string, audience []string) (*Manager, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &Manager{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		issuer:     issuer,
		audience:   audience,
	}, nil
}

// NewManagerWithKeys creates a new JWT manager with existing keys
func NewManagerWithKeys(privateKeyPEM, publicKeyPEM string, issuer string, audience []string) (*Manager, error) {
	// Parse private key
	privBlock, _ := pem.Decode([]byte(privateKeyPEM))
	if privBlock == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse public key
	pubBlock, _ := pem.Decode([]byte(publicKeyPEM))
	if pubBlock == nil {
		return nil, fmt.Errorf("failed to parse public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key type")
	}

	return &Manager{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		audience:   audience,
	}, nil
}

// ExportKeys exports the private and public keys in PEM format
func (m *Manager) ExportKeys() (privateKey, publicKey string, err error) {
	// Export private key
	privBytes := x509.MarshalPKCS1PrivateKey(m.privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	// Export public key
	pubBytes, err := x509.MarshalPKIXPublicKey(m.publicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return string(privPEM), string(pubPEM), nil
}

// CreateTokenPair creates both access and refresh tokens
func (m *Manager) CreateTokenPair(userID, email, name string, accessTokenExpiry, refreshTokenExpiry time.Duration) (*TokenPair, error) {
	now := time.Now()

	// Create access token claims
	accessClaims := &Claims{
		UserID: userID,
		Email:  email,
		Name:   name,
		RegisteredClaims: jwtpkg.RegisteredClaims{
			IssuedAt:  jwtpkg.NewNumericDate(now),
			ExpiresAt: jwtpkg.NewNumericDate(now.Add(accessTokenExpiry)),
			Issuer:    m.issuer,
			Audience:  jwtpkg.ClaimStrings(m.audience),
			Subject:   userID,
		},
	}

	accessToken := jwtpkg.NewWithClaims(jwtpkg.SigningMethodRS256, accessClaims)
	accessTokenStr, err := accessToken.SignedString(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Create refresh token claims
	refreshClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwtpkg.RegisteredClaims{
			IssuedAt:  jwtpkg.NewNumericDate(now),
			ExpiresAt: jwtpkg.NewNumericDate(now.Add(refreshTokenExpiry)),
			Issuer:    m.issuer,
			Audience:  jwtpkg.ClaimStrings(m.audience),
			Subject:   userID,
		},
	}

	refreshToken := jwtpkg.NewWithClaims(jwtpkg.SigningMethodRS256, refreshClaims)
	refreshTokenStr, err := refreshToken.SignedString(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenStr,
		ExpiresIn:    int64(accessTokenExpiry.Seconds()),
	}, nil
}

// VerifyToken verifies a JWT token and returns the claims
func (m *Manager) VerifyToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwtpkg.ParseWithClaims(tokenStr, claims, func(token *jwtpkg.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwtpkg.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// RefreshAccessToken creates a new access token from a refresh token
func (m *Manager) RefreshAccessToken(refreshTokenStr string, accessTokenExpiry time.Duration) (string, error) {
	claims, err := m.VerifyToken(refreshTokenStr)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if token is expired
	if claims.RegisteredClaims.ExpiresAt != nil && claims.RegisteredClaims.ExpiresAt.Before(time.Now()) {
		return "", fmt.Errorf("refresh token has expired")
	}

	// Create new access token with original claims
	now := time.Now()
	newClaims := &Claims{
		UserID: claims.UserID,
		Email:  claims.Email,
		Name:   claims.Name,
		RegisteredClaims: jwtpkg.RegisteredClaims{
			IssuedAt:  jwtpkg.NewNumericDate(now),
			ExpiresAt: jwtpkg.NewNumericDate(now.Add(accessTokenExpiry)),
			Issuer:    m.issuer,
			Audience:  jwtpkg.ClaimStrings(m.audience),
			Subject:   claims.UserID,
		},
	}

	token := jwtpkg.NewWithClaims(jwtpkg.SigningMethodRS256, newClaims)
	accessTokenStr, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return accessTokenStr, nil
}

// IsTokenExpired checks if a token is expired
func (m *Manager) IsTokenExpired(tokenStr string) bool {
	claims := &Claims{}
	_, err := jwtpkg.ParseWithClaims(tokenStr, claims, func(token *jwtpkg.Token) (any, error) {
		return m.publicKey, nil
	})

	// If there's an error, check if it's due to expiration
	if err != nil {
		// In jwt/v5, expired tokens will have an error
		return err.Error() == jwtpkg.ErrTokenExpired.Error()
	}

	if claims.RegisteredClaims.ExpiresAt != nil {
		return claims.RegisteredClaims.ExpiresAt.Before(time.Now())
	}

	return false
}

// GetRemainingTime returns the remaining time before token expiration
func (m *Manager) GetRemainingTime(tokenStr string) time.Duration {
	claims := &Claims{}
	jwtpkg.ParseWithClaims(tokenStr, claims, func(token *jwtpkg.Token) (any, error) {
		return m.publicKey, nil
	})

	if claims.RegisteredClaims.ExpiresAt != nil {
		remaining := time.Until(claims.RegisteredClaims.ExpiresAt.Time)
		if remaining < 0 {
			return 0
		}
		return remaining
	}

	return 0
}

// CreateOAuthTokenPair creates tokens for OAuth flows
func (m *Manager) CreateOAuthTokenPair(userID, email, name, provider, accountID string, accessTokenExpiry, refreshTokenExpiry time.Duration) (*TokenPair, error) {
	now := time.Now()

	// Create access token claims with OAuth info
	accessClaims := &Claims{
		UserID:    userID,
		Email:     email,
		Name:      name,
		Provider:  provider,
		AccountID: accountID,
		RegisteredClaims: jwtpkg.RegisteredClaims{
			IssuedAt:  jwtpkg.NewNumericDate(now),
			ExpiresAt: jwtpkg.NewNumericDate(now.Add(accessTokenExpiry)),
			Issuer:    m.issuer,
			Audience:  jwtpkg.ClaimStrings(m.audience),
			Subject:   userID,
		},
	}

	accessToken := jwtpkg.NewWithClaims(jwtpkg.SigningMethodRS256, accessClaims)
	accessTokenStr, err := accessToken.SignedString(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Create refresh token claims
	refreshClaims := &Claims{
		UserID:    userID,
		Provider:  provider,
		AccountID: accountID,
		RegisteredClaims: jwtpkg.RegisteredClaims{
			IssuedAt:  jwtpkg.NewNumericDate(now),
			ExpiresAt: jwtpkg.NewNumericDate(now.Add(refreshTokenExpiry)),
			Issuer:    m.issuer,
			Audience:  jwtpkg.ClaimStrings(m.audience),
			Subject:   userID,
		},
	}

	refreshToken := jwtpkg.NewWithClaims(jwtpkg.SigningMethodRS256, refreshClaims)
	refreshTokenStr, err := refreshToken.SignedString(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenStr,
		ExpiresIn:    int64(accessTokenExpiry.Seconds()),
	}, nil
}

// EncodeToken encodes a token to base64
func EncodeToken(token string) string {
	return base64.StdEncoding.EncodeToString([]byte(token))
}

// DecodeToken decodes a base64 encoded token
func DecodeToken(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode token: %w", err)
	}
	return string(decoded), nil
}
