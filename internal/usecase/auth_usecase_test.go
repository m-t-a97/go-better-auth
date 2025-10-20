package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/internal/usecase"
)

// Mock implementations for testing

type MockUserRepository struct {
	users map[string]*domain.User
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: make(map[string]*domain.User),
	}
}

func (r *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	if _, exists := r.users[user.Email]; exists {
		return domain.ErrUserAlreadyExists
	}
	r.users[user.Email] = user
	return nil
}

func (r *MockUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	for _, user := range r.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if user, exists := r.users[email]; exists {
		return user, nil
	}
	return nil, domain.ErrUserNotFound
}

func (r *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	if _, exists := r.users[user.Email]; !exists {
		return domain.ErrUserNotFound
	}
	r.users[user.Email] = user
	return nil
}

func (r *MockUserRepository) Delete(ctx context.Context, id string) error {
	for email, user := range r.users {
		if user.ID == id {
			delete(r.users, email)
			return nil
		}
	}
	return domain.ErrUserNotFound
}

type MockSessionRepository struct {
	sessions map[string]*domain.Session
}

func NewMockSessionRepository() *MockSessionRepository {
	return &MockSessionRepository{
		sessions: make(map[string]*domain.Session),
	}
}

func (r *MockSessionRepository) Create(ctx context.Context, session *domain.Session) error {
	r.sessions[session.Token] = session
	return nil
}

func (r *MockSessionRepository) FindByToken(ctx context.Context, token string) (*domain.Session, error) {
	if session, exists := r.sessions[token]; exists {
		return session, nil
	}
	return nil, domain.ErrInvalidToken
}

func (r *MockSessionRepository) FindByUserID(ctx context.Context, userID string) ([]*domain.Session, error) {
	var sessions []*domain.Session
	for _, session := range r.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (r *MockSessionRepository) Update(ctx context.Context, session *domain.Session) error {
	if _, exists := r.sessions[session.Token]; !exists {
		return domain.ErrInvalidToken
	}
	r.sessions[session.Token] = session
	return nil
}

func (r *MockSessionRepository) Delete(ctx context.Context, id string) error {
	for token, session := range r.sessions {
		if session.ID == id {
			delete(r.sessions, token)
			return nil
		}
	}
	return domain.ErrInvalidToken
}

func (r *MockSessionRepository) DeleteByToken(ctx context.Context, token string) error {
	delete(r.sessions, token)
	return nil
}

func (r *MockSessionRepository) DeleteExpired(ctx context.Context) error {
	now := time.Now()
	for token, session := range r.sessions {
		if now.After(session.ExpiresAt) {
			delete(r.sessions, token)
		}
	}
	return nil
}

type MockAccountRepository struct {
	accounts map[string]*domain.Account
}

func NewMockAccountRepository() *MockAccountRepository {
	return &MockAccountRepository{
		accounts: make(map[string]*domain.Account),
	}
}

func (r *MockAccountRepository) Create(ctx context.Context, account *domain.Account) error {
	key := account.UserID + ":" + account.ProviderId
	r.accounts[key] = account
	return nil
}

func (r *MockAccountRepository) FindByUserIDAndProvider(ctx context.Context, userID, providerID string) (*domain.Account, error) {
	key := userID + ":" + providerID
	if account, exists := r.accounts[key]; exists {
		return account, nil
	}
	return nil, domain.ErrUserNotFound
}

func (r *MockAccountRepository) FindByProviderAccountID(ctx context.Context, providerID, accountID string) (*domain.Account, error) {
	for _, account := range r.accounts {
		if account.ProviderId == providerID && account.AccountID == accountID {
			return account, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *MockAccountRepository) Update(ctx context.Context, account *domain.Account) error {
	key := account.UserID + ":" + account.ProviderId
	r.accounts[key] = account
	return nil
}

func (r *MockAccountRepository) Delete(ctx context.Context, id string) error {
	for key, account := range r.accounts {
		if account.ID == id {
			delete(r.accounts, key)
			return nil
		}
	}
	return domain.ErrUserNotFound
}

func (r *MockAccountRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Account, error) {
	var accounts []*domain.Account
	for _, account := range r.accounts {
		if account.UserID == userID {
			accounts = append(accounts, account)
		}
	}
	return accounts, nil
}

type MockVerificationRepository struct {
	verifications map[string]*domain.Verification
}

func NewMockVerificationRepository() *MockVerificationRepository {
	return &MockVerificationRepository{
		verifications: make(map[string]*domain.Verification),
	}
}

func (r *MockVerificationRepository) Create(ctx context.Context, verification *domain.Verification) error {
	r.verifications[verification.Value] = verification
	return nil
}

func (r *MockVerificationRepository) FindByIdentifierAndValue(ctx context.Context, identifier, value string) (*domain.Verification, error) {
	if verification, exists := r.verifications[value]; exists {
		return verification, nil
	}
	return nil, domain.ErrInvalidToken
}

func (r *MockVerificationRepository) Delete(ctx context.Context, id string) error {
	for value, verification := range r.verifications {
		if verification.ID == id {
			delete(r.verifications, value)
			return nil
		}
	}
	return domain.ErrInvalidToken
}

func (r *MockVerificationRepository) DeleteExpired(ctx context.Context) error {
	now := time.Now()
	for value, verification := range r.verifications {
		if now.After(verification.ExpiresAt) {
			delete(r.verifications, value)
		}
	}
	return nil
}

// Tests

func TestSignUpEmail(t *testing.T) {
	// Setup
	userRepo := NewMockUserRepository()
	sessionRepo := NewMockSessionRepository()
	accountRepo := NewMockAccountRepository()
	verificationRepo := NewMockVerificationRepository()
	passwordHasher := usecase.NewScryptPasswordHasher()

	authUseCase := usecase.NewAuthUseCase(
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
		passwordHasher,
		nil,
		&usecase.AuthConfig{
			BaseURL:                  "http://localhost:3000",
			SessionExpiresIn:         7 * 24 * time.Hour,
			RequireEmailVerification: false,
			AutoSignIn:               true,
		},
	)

	// Test successful signup
	t.Run("successful signup", func(t *testing.T) {
		ctx := context.Background()
		input := &usecase.SignUpEmailInput{
			Email:    "test@example.com",
			Password: "secure123",
			Name:     "Test User",
		}

		output, err := authUseCase.SignUpEmail(ctx, input)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if output.User.Email != input.Email {
			t.Errorf("Expected email %s, got %s", input.Email, output.User.Email)
		}

		if output.Session == nil {
			t.Error("Expected session to be created")
		}
	})

	// Test duplicate email
	t.Run("duplicate email", func(t *testing.T) {
		ctx := context.Background()
		input := &usecase.SignUpEmailInput{
			Email:    "test@example.com",
			Password: "secure123",
			Name:     "Test User 2",
		}

		_, err := authUseCase.SignUpEmail(ctx, input)
		if err != domain.ErrUserAlreadyExists {
			t.Errorf("Expected ErrUserAlreadyExists, got %v", err)
		}
	})
}

func TestSignInEmail(t *testing.T) {
	// Setup
	userRepo := NewMockUserRepository()
	sessionRepo := NewMockSessionRepository()
	accountRepo := NewMockAccountRepository()
	verificationRepo := NewMockVerificationRepository()
	passwordHasher := usecase.NewScryptPasswordHasher()

	authUseCase := usecase.NewAuthUseCase(
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
		passwordHasher,
		nil,
		&usecase.AuthConfig{
			BaseURL:                  "http://localhost:3000",
			SessionExpiresIn:         7 * 24 * time.Hour,
			RequireEmailVerification: false,
			AutoSignIn:               true,
		},
	)

	// Create a user first
	ctx := context.Background()
	signupInput := &usecase.SignUpEmailInput{
		Email:    "signin@example.com",
		Password: "secure123",
		Name:     "Sign In User",
	}
	authUseCase.SignUpEmail(ctx, signupInput)

	// Test successful signin
	t.Run("successful signin", func(t *testing.T) {
		input := &usecase.SignInEmailInput{
			Email:    "signin@example.com",
			Password: "secure123",
		}

		output, err := authUseCase.SignInEmail(ctx, input)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if output.User.Email != input.Email {
			t.Errorf("Expected email %s, got %s", input.Email, output.User.Email)
		}

		if output.Session == nil {
			t.Error("Expected session to be created")
		}
	})

	// Test invalid password
	t.Run("invalid password", func(t *testing.T) {
		input := &usecase.SignInEmailInput{
			Email:    "signin@example.com",
			Password: "wrongpassword",
		}

		_, err := authUseCase.SignInEmail(ctx, input)
		if err != domain.ErrInvalidCredentials {
			t.Errorf("Expected ErrInvalidCredentials, got %v", err)
		}
	})

	// Test non-existent user
	t.Run("non-existent user", func(t *testing.T) {
		input := &usecase.SignInEmailInput{
			Email:    "nonexistent@example.com",
			Password: "password",
		}

		_, err := authUseCase.SignInEmail(ctx, input)
		if err != domain.ErrInvalidCredentials {
			t.Errorf("Expected ErrInvalidCredentials, got %v", err)
		}
	})
}

func TestPasswordHashing(t *testing.T) {
	hasher := usecase.NewScryptPasswordHasher()

	password := "mysecretpassword"

	// Test hashing
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test verification with correct password
	if !hasher.Verify(password, hash) {
		t.Error("Expected password verification to succeed")
	}

	// Test verification with wrong password
	if hasher.Verify("wrongpassword", hash) {
		t.Error("Expected password verification to fail")
	}
}

func TestSessionManagement(t *testing.T) {
	// Setup
	userRepo := NewMockUserRepository()
	sessionRepo := NewMockSessionRepository()
	accountRepo := NewMockAccountRepository()
	verificationRepo := NewMockVerificationRepository()
	passwordHasher := usecase.NewScryptPasswordHasher()

	authUseCase := usecase.NewAuthUseCase(
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
		passwordHasher,
		nil,
		&usecase.AuthConfig{
			BaseURL:                  "http://localhost:3000",
			SessionExpiresIn:         7 * 24 * time.Hour,
			RequireEmailVerification: false,
			AutoSignIn:               true,
		},
	)

	// Create user and session
	ctx := context.Background()
	signupInput := &usecase.SignUpEmailInput{
		Email:    "session@example.com",
		Password: "secure123",
		Name:     "Session User",
	}
	output, _ := authUseCase.SignUpEmail(ctx, signupInput)
	token := output.Session.Token

	// Test get session
	t.Run("get valid session", func(t *testing.T) {
		session, user, err := authUseCase.GetSession(ctx, token)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if session.UserID != user.ID {
			t.Error("Session user ID doesn't match user ID")
		}
	})

	// Test signout
	t.Run("signout", func(t *testing.T) {
		err := authUseCase.SignOut(ctx, token)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		// Try to get session after signout
		_, _, err = authUseCase.GetSession(ctx, token)
		if err != domain.ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken after signout, got %v", err)
		}
	})
}
