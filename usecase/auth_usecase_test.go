package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/usecase"
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
			Password: "SecurePass123!",
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
			Password: "SecurePass123!",
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
		Password: "SecurePass123!",
		Name:     "Sign In User",
	}
	authUseCase.SignUpEmail(ctx, signupInput)

	// Test successful signin
	t.Run("successful signin", func(t *testing.T) {
		input := &usecase.SignInEmailInput{
			Email:    "signin@example.com",
			Password: "SecurePass123!",
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
		Password: "SecurePass123!",
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

func TestRefreshSession(t *testing.T) {
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
			SessionExpiresIn:         24 * time.Hour,
			RequireEmailVerification: false,
			AutoSignIn:               true,
		},
	)

	ctx := context.Background()

	// Create user and session
	user := &domain.User{
		ID:            "user-123",
		Email:         "refresh@example.com",
		Name:          "Refresh User",
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	userRepo.Create(ctx, user)

	session := &domain.Session{
		ID:        "session-123",
		UserID:    user.ID,
		Token:     usecase.GenerateToken(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sessionRepo.Create(ctx, session)

	// Get original expiration time
	originalExpiresAt := session.ExpiresAt

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Refresh session
	output, err := authUseCase.RefreshSession(ctx, &usecase.RefreshSessionInput{
		Token: session.Token,
	})

	if err != nil {
		t.Fatalf("RefreshSession failed: %v", err)
	}

	if output.Session == nil {
		t.Fatal("Session should not be nil")
	}

	if output.User == nil {
		t.Fatal("User should not be nil")
	}

	// Check that expiration was extended
	if output.Session.ExpiresAt.Before(originalExpiresAt) {
		t.Error("Session expiration should be extended")
	}

	// Session should be usable
	_, _, err = authUseCase.GetSession(ctx, session.Token)
	if err != nil {
		t.Fatalf("Session should be usable after refresh: %v", err)
	}
}

func TestRefreshExpiredSession(t *testing.T) {
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
			SessionExpiresIn:         24 * time.Hour,
			RequireEmailVerification: false,
			AutoSignIn:               true,
		},
	)

	ctx := context.Background()

	// Create user and expired session
	user := &domain.User{
		ID:            "user-123",
		Email:         "expired@example.com",
		Name:          "Expired User",
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	userRepo.Create(ctx, user)

	session := &domain.Session{
		ID:        "session-123",
		UserID:    user.ID,
		Token:     usecase.GenerateToken(),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sessionRepo.Create(ctx, session)

	// Try to refresh expired session
	_, err := authUseCase.RefreshSession(ctx, &usecase.RefreshSessionInput{
		Token: session.Token,
	})

	if err != domain.ErrSessionExpired {
		t.Errorf("Expected ErrSessionExpired, got %v", err)
	}
}

func TestCleanExpiredSessions(t *testing.T) {
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
			SessionExpiresIn:         24 * time.Hour,
			RequireEmailVerification: false,
			AutoSignIn:               true,
		},
	)

	ctx := context.Background()

	// Create user
	user := &domain.User{
		ID:            "user-123",
		Email:         "clean@example.com",
		Name:          "Clean User",
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	userRepo.Create(ctx, user)

	// Create multiple sessions - some expired, some valid
	for i := 0; i < 3; i++ {
		session := &domain.Session{
			ID:        "session-" + string(rune(i)),
			UserID:    user.ID,
			Token:     usecase.GenerateToken(),
			ExpiresAt: time.Now().Add(-1 * time.Hour), // All expired
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		sessionRepo.Create(ctx, session)
	}

	// Add a valid session
	validSession := &domain.Session{
		ID:        "session-valid",
		UserID:    user.ID,
		Token:     usecase.GenerateToken(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Valid
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sessionRepo.Create(ctx, validSession)

	// Clean expired sessions
	err := authUseCase.CleanExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredSessions failed: %v", err)
	}

	// Check that expired sessions were deleted
	sessions, _ := sessionRepo.FindByUserID(ctx, user.ID)
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session after cleanup, got %d", len(sessions))
	}

	// Verify the remaining session is the valid one
	remainingSession, _ := sessionRepo.FindByToken(ctx, validSession.Token)
	if remainingSession == nil {
		t.Fatal("Valid session should still exist")
	}
}

// TestPasswordPolicyValidation tests password policy enforcement
func TestPasswordPolicyValidation(t *testing.T) {
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

	ctx := context.Background()

	testCases := []struct {
		name        string
		password    string
		shouldError bool
		errorCode   string
	}{
		{
			name:        "valid password",
			password:    "SecurePass123!",
			shouldError: false,
		},
		{
			name:        "too short password",
			password:    "Short1!",
			shouldError: true,
			errorCode:   "weak_password",
		},
		{
			name:        "missing uppercase",
			password:    "securep ass123!",
			shouldError: true,
			errorCode:   "weak_password",
		},
		{
			name:        "missing lowercase",
			password:    "SECUREPASS123!",
			shouldError: true,
			errorCode:   "weak_password",
		},
		{
			name:        "missing digit",
			password:    "SecurePass!",
			shouldError: true,
			errorCode:   "weak_password",
		},
		{
			name:        "missing special character",
			password:    "SecurePass123",
			shouldError: true,
			errorCode:   "weak_password",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &usecase.SignUpEmailInput{
				Email:    "test-" + tc.name + "@example.com",
				Password: tc.password,
				Name:     "Test User",
			}

			_, err := authUseCase.SignUpEmail(ctx, input)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for password: %s", tc.password)
				}
				if authErr, ok := err.(*domain.AuthError); ok {
					if authErr.Code != tc.errorCode {
						t.Errorf("Expected error code %s, got %s", tc.errorCode, authErr.Code)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestSignUpEmailDuplicateEmail tests duplicate email prevention
func TestSignUpEmailDuplicateEmail(t *testing.T) {
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

	ctx := context.Background()
	email := "duplicate@example.com"
	password := "SecurePass123!"

	// First signup should succeed
	_, err := authUseCase.SignUpEmail(ctx, &usecase.SignUpEmailInput{
		Email:    email,
		Password: password,
		Name:     "First User",
	})
	if err != nil {
		t.Fatalf("First signup failed: %v", err)
	}

	// Second signup with same email should fail
	_, err = authUseCase.SignUpEmail(ctx, &usecase.SignUpEmailInput{
		Email:    email,
		Password: password,
		Name:     "Second User",
	})
	if err != domain.ErrUserAlreadyExists {
		t.Errorf("Expected ErrUserAlreadyExists, got %v", err)
	}
}

// TestChangePasswordWithValidation tests password change with policy validation
func TestChangePasswordWithValidation(t *testing.T) {
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

	ctx := context.Background()

	// Create a user
	input := &usecase.SignUpEmailInput{
		Email:    "changepass@example.com",
		Password: "SecurePass123!",
		Name:     "Test User",
	}
	output, err := authUseCase.SignUpEmail(ctx, input)
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	// Test changing to weak password
	err = authUseCase.ChangePassword(ctx, output.User.ID, "SecurePass123!", "weak", false)
	if err == nil {
		t.Error("Expected error for weak password")
	}

	// Test changing to valid password
	newPassword := "NewSecure123!"
	err = authUseCase.ChangePassword(ctx, output.User.ID, "SecurePass123!", newPassword, false)
	if err != nil {
		t.Errorf("ChangePassword failed: %v", err)
	}

	// Verify the new password works
	signInOutput, err := authUseCase.SignInEmail(ctx, &usecase.SignInEmailInput{
		Email:    "changepass@example.com",
		Password: newPassword,
	})
	if err != nil {
		t.Errorf("SignIn with new password failed: %v", err)
	}
	if signInOutput.User.ID != output.User.ID {
		t.Error("Sign in returned wrong user")
	}
}
