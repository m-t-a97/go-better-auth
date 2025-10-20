package usecase

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateToken generates a secure random token
func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
