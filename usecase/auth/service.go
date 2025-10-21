package auth

import (
	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
)

// Service provides authentication use cases
type Service struct {
	config           *domain.Config
	userRepo         user.Repository
	sessionRepo      session.Repository
	accountRepo      account.Repository
	verificationRepo verification.Repository
}

// NewService creates a new authentication service
func NewService(
	config *domain.Config,
	userRepo user.Repository,
	sessionRepo session.Repository,
	accountRepo account.Repository,
	verificationRepo verification.Repository,
) *Service {
	return &Service{
		config:           config,
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		accountRepo:      accountRepo,
		verificationRepo: verificationRepo,
	}
}
