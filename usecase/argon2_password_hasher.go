package usecase

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

// Argon2PasswordHasher implements password hashing using argon2
type Argon2PasswordHasher struct{}

func NewArgon2PasswordHasher() *Argon2PasswordHasher {
	return &Argon2PasswordHasher{}
}

func (h *Argon2PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.Key([]byte(password), salt, 1, 64*1024, 4, 32)

	// Combine salt and hash
	combined := append(salt, hash...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

func (h *Argon2PasswordHasher) Verify(password, encoded string) bool {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	if len(decoded) < 48 {
		return false
	}

	salt := decoded[:16]
	hash := decoded[16:]

	newHash := argon2.Key([]byte(password), salt, 1, 64*1024, 4, 32)

	// Constant time comparison
	if len(newHash) != len(hash) {
		return false
	}

	var v byte
	for i := range hash {
		v |= hash[i] ^ newHash[i]
	}

	return v == 0
}
