package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"

	"github.com/m-t-a97/go-better-auth/internal/domain"
)

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

// AuthConfig holds the configuration for authentication
type AuthConfig struct {
	BaseURL                  string
	SessionExpiresIn         time.Duration
	VerificationTokenExpiry  time.Duration
	RequireEmailVerification bool
	AutoSignIn               bool
}

// AuthUseCase handles authentication business logic
type AuthUseCase struct {
	userRepo         domain.UserRepository
	sessionRepo      domain.SessionRepository
	accountRepo      domain.AccountRepository
	verificationRepo domain.VerificationRepository
	passwordHasher   PasswordHasher
	emailSender      EmailSender
	config           *AuthConfig
}

// NewAuthUseCase creates a new authentication use case
func NewAuthUseCase(
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	accountRepo domain.AccountRepository,
	verificationRepo domain.VerificationRepository,
	passwordHasher PasswordHasher,
	emailSender EmailSender,
	config *AuthConfig,
) *AuthUseCase {
	if config.SessionExpiresIn == 0 {
		config.SessionExpiresIn = 7 * 24 * time.Hour // 7 days default
	}
	if config.VerificationTokenExpiry == 0 {
		config.VerificationTokenExpiry = 24 * time.Hour // 24 hours default
	}
	return &AuthUseCase{
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		accountRepo:      accountRepo,
		verificationRepo: verificationRepo,
		passwordHasher:   passwordHasher,
		emailSender:      emailSender,
		config:           config,
	}
}

// SignUpEmailInput represents the input for email signup
type SignUpEmailInput struct {
	Email    string
	Password string
	Name     string
	Image    *string
}

// SignUpEmailOutput represents the output of email signup
type SignUpEmailOutput struct {
	User    *domain.User
	Session *domain.Session
}

// SignUpEmail registers a new user with email and password
func (uc *AuthUseCase) SignUpEmail(ctx context.Context, input *SignUpEmailInput) (*SignUpEmailOutput, error) {
	// Check if user already exists
	existingUser, err := uc.userRepo.FindByEmail(ctx, input.Email)
	if err == nil && existingUser != nil {
		return nil, domain.ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := uc.passwordHasher.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &domain.User{
		ID:            uuid.New().String(),
		Email:         input.Email,
		Name:          input.Name,
		Image:         input.Image,
		EmailVerified: !uc.config.RequireEmailVerification,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Create account with hashed password
	account := &domain.Account{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		AccountID:  user.Email,
		ProviderId: "credential",
		Password:   &hashedPassword,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := uc.accountRepo.Create(ctx, account); err != nil {
		return nil, err
	}

	// Send verification email if required
	if uc.config.RequireEmailVerification && uc.emailSender != nil {
		token := generateToken()
		verification := &domain.Verification{
			ID:         uuid.New().String(),
			Identifier: user.Email,
			Value:      token,
			ExpiresAt:  time.Now().Add(uc.config.VerificationTokenExpiry),
			CreatedAt:  time.Now(),
		}

		if err := uc.verificationRepo.Create(ctx, verification); err != nil {
			return nil, err
		}

		url := uc.config.BaseURL + "/api/auth/verify-email?token=" + token
		if err := uc.emailSender.SendVerificationEmail(ctx, user.Email, token, url); err != nil {
			// Log error but don't fail signup
		}
	}

	var session *domain.Session
	// Auto sign in if enabled and email verification not required or not enabled
	if uc.config.AutoSignIn && (!uc.config.RequireEmailVerification || user.EmailVerified) {
		session, err = uc.createSession(ctx, user.ID, nil, nil)
		if err != nil {
			return nil, err
		}
	}

	return &SignUpEmailOutput{
		User:    user,
		Session: session,
	}, nil
}

// SignInEmailInput represents the input for email signin
type SignInEmailInput struct {
	Email      string
	Password   string
	RememberMe bool
	IPAddress  *string
	UserAgent  *string
}

// SignInEmailOutput represents the output of email signin
type SignInEmailOutput struct {
	User    *domain.User
	Session *domain.Session
}

// SignInEmail authenticates a user with email and password
func (uc *AuthUseCase) SignInEmail(ctx context.Context, input *SignInEmailInput) (*SignInEmailOutput, error) {
	// Find user
	user, err := uc.userRepo.FindByEmail(ctx, input.Email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// Check email verification if required
	if uc.config.RequireEmailVerification && !user.EmailVerified {
		// Send verification email
		if uc.emailSender != nil {
			token := generateToken()
			verification := &domain.Verification{
				ID:         uuid.New().String(),
				Identifier: user.Email,
				Value:      token,
				ExpiresAt:  time.Now().Add(uc.config.VerificationTokenExpiry),
				CreatedAt:  time.Now(),
			}

			uc.verificationRepo.Create(ctx, verification)
			url := uc.config.BaseURL + "/api/auth/verify-email?token=" + token
			uc.emailSender.SendVerificationEmail(ctx, user.Email, token, url)
		}
		return nil, domain.ErrEmailNotVerified
	}

	// Find account
	account, err := uc.accountRepo.FindByUserIDAndProvider(ctx, user.ID, "credential")
	if err != nil || account.Password == nil {
		return nil, domain.ErrInvalidCredentials
	}

	// Verify password
	if !uc.passwordHasher.Verify(input.Password, *account.Password) {
		return nil, domain.ErrInvalidCredentials
	}

	// Create session
	expiresIn := uc.config.SessionExpiresIn
	if input.RememberMe {
		expiresIn = 30 * 24 * time.Hour // 30 days
	}

	session, err := uc.createSessionWithExpiry(ctx, user.ID, expiresIn, input.IPAddress, input.UserAgent)
	if err != nil {
		return nil, err
	}

	return &SignInEmailOutput{
		User:    user,
		Session: session,
	}, nil
}

// GetSession retrieves a session by token
func (uc *AuthUseCase) GetSession(ctx context.Context, token string) (*domain.Session, *domain.User, error) {
	session, err := uc.sessionRepo.FindByToken(ctx, token)
	if err != nil {
		return nil, nil, domain.ErrInvalidToken
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		uc.sessionRepo.Delete(ctx, session.ID)
		return nil, nil, domain.ErrSessionExpired
	}

	// Get user
	user, err := uc.userRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, domain.ErrUserNotFound
	}

	return session, user, nil
}

// SignOut deletes a session
func (uc *AuthUseCase) SignOut(ctx context.Context, token string) error {
	return uc.sessionRepo.DeleteByToken(ctx, token)
}

// SendVerificationEmail sends a verification email to the user
func (uc *AuthUseCase) SendVerificationEmail(ctx context.Context, email string) error {
	if uc.emailSender == nil {
		return domain.ErrInvalidRequest
	}

	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if user.EmailVerified {
		return nil // Already verified
	}

	token := generateToken()
	verification := &domain.Verification{
		ID:         uuid.New().String(),
		Identifier: email,
		Value:      token,
		ExpiresAt:  time.Now().Add(uc.config.VerificationTokenExpiry),
		CreatedAt:  time.Now(),
	}

	if err := uc.verificationRepo.Create(ctx, verification); err != nil {
		return err
	}

	url := uc.config.BaseURL + "/api/auth/verify-email?token=" + token
	return uc.emailSender.SendVerificationEmail(ctx, email, token, url)
}

// VerifyEmail verifies a user's email address
func (uc *AuthUseCase) VerifyEmail(ctx context.Context, token string) (*domain.User, error) {
	// Find verification
	// Note: We need to search by value (token) but identifier is unknown
	// This is a simplified implementation
	verification, err := uc.findVerificationByToken(ctx, token)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}

	// Check if expired
	if time.Now().After(verification.ExpiresAt) {
		uc.verificationRepo.Delete(ctx, verification.ID)
		return nil, domain.ErrInvalidToken
	}

	// Find and update user
	user, err := uc.userRepo.FindByEmail(ctx, verification.Identifier)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	if err := uc.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	// Delete verification token
	uc.verificationRepo.Delete(ctx, verification.ID)

	return user, nil
}

// RequestPasswordReset sends a password reset email
func (uc *AuthUseCase) RequestPasswordReset(ctx context.Context, email string) error {
	if uc.emailSender == nil {
		return domain.ErrInvalidRequest
	}

	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// Don't reveal if user exists
		return nil
	}

	token := generateToken()
	verification := &domain.Verification{
		ID:         uuid.New().String(),
		Identifier: user.ID,
		Value:      token,
		ExpiresAt:  time.Now().Add(uc.config.VerificationTokenExpiry),
		CreatedAt:  time.Now(),
	}

	if err := uc.verificationRepo.Create(ctx, verification); err != nil {
		return err
	}

	url := uc.config.BaseURL + "/reset-password?token=" + token
	return uc.emailSender.SendPasswordResetEmail(ctx, email, token, url)
}

// ResetPassword resets a user's password using a token
func (uc *AuthUseCase) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Find verification
	verification, err := uc.findVerificationByToken(ctx, token)
	if err != nil {
		return domain.ErrInvalidToken
	}

	// Check if expired
	if time.Now().After(verification.ExpiresAt) {
		uc.verificationRepo.Delete(ctx, verification.ID)
		return domain.ErrInvalidToken
	}

	// Hash new password
	hashedPassword, err := uc.passwordHasher.Hash(newPassword)
	if err != nil {
		return err
	}

	// Update account
	account, err := uc.accountRepo.FindByUserIDAndProvider(ctx, verification.Identifier, "credential")
	if err != nil {
		return domain.ErrUserNotFound
	}

	account.Password = &hashedPassword
	account.UpdatedAt = time.Now()

	if err := uc.accountRepo.Update(ctx, account); err != nil {
		return err
	}

	// Delete verification token
	uc.verificationRepo.Delete(ctx, verification.ID)

	return nil
}

// ChangePassword changes a user's password
func (uc *AuthUseCase) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string, revokeOtherSessions bool) error {
	// Verify current password
	account, err := uc.accountRepo.FindByUserIDAndProvider(ctx, userID, "credential")
	if err != nil || account.Password == nil {
		return domain.ErrInvalidCredentials
	}

	if !uc.passwordHasher.Verify(currentPassword, *account.Password) {
		return domain.ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := uc.passwordHasher.Hash(newPassword)
	if err != nil {
		return err
	}

	// Update account
	account.Password = &hashedPassword
	account.UpdatedAt = time.Now()

	if err := uc.accountRepo.Update(ctx, account); err != nil {
		return err
	}

	// Revoke other sessions if requested
	if revokeOtherSessions {
		sessions, err := uc.sessionRepo.FindByUserID(ctx, userID)
		if err == nil {
			for _, session := range sessions {
				uc.sessionRepo.Delete(ctx, session.ID)
			}
		}
	}

	return nil
}

// Helper functions

func (uc *AuthUseCase) createSession(ctx context.Context, userID string, ipAddress, userAgent *string) (*domain.Session, error) {
	return uc.createSessionWithExpiry(ctx, userID, uc.config.SessionExpiresIn, ipAddress, userAgent)
}

func (uc *AuthUseCase) createSessionWithExpiry(ctx context.Context, userID string, expiresIn time.Duration, ipAddress, userAgent *string) (*domain.Session, error) {
	session := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     generateToken(),
		ExpiresAt: time.Now().Add(expiresIn),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := uc.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

func (uc *AuthUseCase) findVerificationByToken(ctx context.Context, token string) (*domain.Verification, error) {
	// This is a simplified implementation
	// In a real implementation, you would need to query by value field
	// For now, we'll assume the repository can handle this
	return uc.verificationRepo.FindByIdentifierAndValue(ctx, "", token)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

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
