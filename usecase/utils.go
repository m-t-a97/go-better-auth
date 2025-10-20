package usecase

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/m-t-a97/go-better-auth/domain"
)

// GenerateToken generates a secure random token
func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// ValidatePassword checks password policy compliance
// Minimum 8 characters required, with at least one uppercase, one lowercase, one digit, and one special character
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return &domain.AuthError{
			Code:    "weak_password",
			Message: "Password must be at least 8 characters long",
			Status:  400,
		}
	}

	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	for _, char := range password {
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
		} else if char >= 'a' && char <= 'z' {
			hasLower = true
		} else if char >= '0' && char <= '9' {
			hasDigit = true
		} else if len([]rune(specialChars)) > 0 {
			for _, s := range specialChars {
				if char == s {
					hasSpecial = true
					break
				}
			}
		}
	}

	if !hasUpper {
		return &domain.AuthError{
			Code:    "weak_password",
			Message: "Password must contain at least one uppercase letter",
			Status:  400,
		}
	}
	if !hasLower {
		return &domain.AuthError{
			Code:    "weak_password",
			Message: "Password must contain at least one lowercase letter",
			Status:  400,
		}
	}
	if !hasDigit {
		return &domain.AuthError{
			Code:    "weak_password",
			Message: "Password must contain at least one digit",
			Status:  400,
		}
	}
	if !hasSpecial {
		return &domain.AuthError{
			Code:    "weak_password",
			Message: "Password must contain at least one special character",
			Status:  400,
		}
	}

	return nil
}
