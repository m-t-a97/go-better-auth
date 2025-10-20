package usecase

import (
	"context"

	"github.com/m-t-a97/go-better-auth/domain"
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	FindByID(ctx context.Context, id string) (*domain.User, error)
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id string) error
}

// SessionRepository defines the interface for session data operations
type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
	FindByToken(ctx context.Context, token string) (*domain.Session, error)
	FindByUserID(ctx context.Context, userID string) ([]*domain.Session, error)
	Update(ctx context.Context, session *domain.Session) error
	Delete(ctx context.Context, id string) error
	DeleteByToken(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context) error
}

// AccountRepository defines the interface for account data operations
type AccountRepository interface {
	Create(ctx context.Context, account *domain.Account) error
	FindByUserIDAndProvider(ctx context.Context, userID, providerID string) (*domain.Account, error)
	FindByProviderAccountID(ctx context.Context, providerID, accountID string) (*domain.Account, error)
	Update(ctx context.Context, account *domain.Account) error
	Delete(ctx context.Context, id string) error
	ListByUserID(ctx context.Context, userID string) ([]*domain.Account, error)
}

// VerificationRepository defines the interface for verification token operations
type VerificationRepository interface {
	Create(ctx context.Context, verification *domain.Verification) error
	FindByIdentifierAndValue(ctx context.Context, identifier, value string) (*domain.Verification, error)
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}

// PasswordHasher defines the interface for password hashing
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

// EmailSender defines the interface for sending emails
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, email, token, url string) error
	SendPasswordResetEmail(ctx context.Context, email, token, url string) error
}

// OAuthProvider defines the interface for OAuth providers
type OAuthProvider interface {
	GetAuthURL(state, redirectURI string) string
	ExchangeCode(ctx context.Context, code, redirectURI string) (*domain.OAuthTokens, error)
	GetUserInfo(ctx context.Context, accessToken string) (*domain.OAuthUserInfo, error)
	GetProviderID() string
}

// SignUpUseCase defines the interface for user registration
type SignUpUseCase interface {
	SignUpEmail(ctx context.Context, input *domain.SignUpEmailInput) (*domain.SignUpEmailOutput, error)
}

// SignInUseCase defines the interface for user authentication
type SignInUseCase interface {
	SignInEmail(ctx context.Context, input *domain.SignInEmailInput) (*domain.SignInEmailOutput, error)
}

// SessionUseCase defines the interface for session management
type SessionUseCase interface {
	GetSession(ctx context.Context, token string) (*domain.Session, *domain.User, error)
	RefreshSession(ctx context.Context, input *domain.RefreshSessionInput) (*domain.RefreshSessionOutput, error)
	CleanExpiredSessions(ctx context.Context) error
	SignOut(ctx context.Context, token string) error
}

// EmailVerificationUseCase defines the interface for email verification
type EmailVerificationUseCase interface {
	SendVerificationEmail(ctx context.Context, email string) error
	VerifyEmail(ctx context.Context, token string) (*domain.User, error)
}

// PasswordResetUseCase defines the interface for password reset
type PasswordResetUseCase interface {
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
}

// PasswordChangeUseCase defines the interface for password change
type PasswordChangeUseCase interface {
	ChangePassword(ctx context.Context, userID, currentPassword, newPassword string, revokeOtherSessions bool) error
}
