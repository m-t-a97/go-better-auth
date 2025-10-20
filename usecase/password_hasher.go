package usecase

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/scrypt"
)

// ScryptPasswordHasher implements password hashing using scrypt
type ScryptPasswordHasher struct{}

func NewScryptPasswordHasher() *ScryptPasswordHasher {
	return &ScryptPasswordHasher{}
}

func (h *ScryptPasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	// Combine salt and hash
	combined := append(salt, hash...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

func (h *ScryptPasswordHasher) Verify(password, encoded string) bool {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	if len(decoded) < 48 {
		return false
	}

	salt := decoded[:16]
	hash := decoded[16:]

	newHash, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return false
	}

	// Constant time comparison
	if len(newHash) != len(hash) {
		return false
	}

	var v byte
	for i := 0; i < len(hash); i++ {
		v |= hash[i] ^ newHash[i]
	}

	return v == 0
}
