package auth

import (
	"time"

	"github.com/google/uuid"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
)

func createTestConfig() *domain.Config {
	config := &domain.Config{}
	config.ApplyDefaults()
	return config
}

func createTestUser() *user.User {
	return &user.User{
		ID:            uuid.New().String(),
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func createTestAccount(userID string, password *string) *account.Account {
	return &account.Account{
		ID:         uuid.New().String(),
		UserID:     userID,
		ProviderID: account.ProviderCredential,
		Password:   password,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

func createTestSession() *session.Session {
	return &session.Session{
		ID:        uuid.New().String(),
		UserID:    uuid.New().String(),
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
