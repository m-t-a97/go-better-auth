package main

import (
	"fmt"
	"log"
	"time"

	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/repository/memory"
)

func main() {
	// ===== 1. Initialize Auth System =====
	fmt.Println("=== Initializing Auth System ===")

	auth, err := gobetterauth.New(&domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "this-is-a-very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}
	fmt.Println("✓ Auth system initialized successfully")

	// ===== 2. Password Hashing =====
	fmt.Println("\n=== Password Hashing with Argon2 ===")

	hasher := auth.PasswordHasher()
	password := "MySecurePassword@123"

	hash, err := hasher.Hash(password)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	fmt.Printf("✓ Password hashed: %s\n", hash[:50]+"...")

	verified, err := hasher.Verify(password, hash)
	if err != nil {
		log.Fatalf("Failed to verify password: %v", err)
	}
	fmt.Printf("✓ Password verification: %v\n", verified)

	// ===== 3. Secret Generation =====
	fmt.Println("\n=== Secret Generation ===")

	generator := auth.SecretGenerator()

	secret, err := generator.GenerateSecretDefault()
	if err != nil {
		log.Fatalf("Failed to generate secret: %v", err)
	}
	fmt.Printf("✓ Generated secret: %s\n", secret[:20]+"...")

	err = generator.ValidateSecret(secret)
	if err != nil {
		log.Fatalf("Secret validation failed: %v", err)
	}
	fmt.Println("✓ Secret validation passed")

	// ===== 4. User Management =====
	fmt.Println("\n=== User Management ===")

	userRepo := memory.NewUserRepository()

	// Create user
	newUser := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err = userRepo.Create(newUser)
	if err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}
	fmt.Printf("✓ Created user: ID=%s, Email=%s\n", newUser.ID[:8]+"...", newUser.Email)

	// Find user by ID
	foundUser, err := userRepo.FindByID(newUser.ID)
	if err != nil {
		log.Fatalf("Failed to find user: %v", err)
	}
	fmt.Printf("✓ Found user by ID: %s\n", foundUser.Name)

	// Find user by email
	foundByEmail, err := userRepo.FindByEmail("john@example.com")
	if err != nil {
		log.Fatalf("Failed to find user by email: %v", err)
	}
	fmt.Printf("✓ Found user by email: %s\n", foundByEmail.Name)

	// Check existence
	exists, _ := userRepo.ExistsByEmail("john@example.com")
	fmt.Printf("✓ User exists by email: %v\n", exists)

	// Create more users
	for i := 2; i <= 3; i++ {
		u := &user.User{
			Name:  fmt.Sprintf("User %d", i),
			Email: fmt.Sprintf("user%d@example.com", i),
		}
		userRepo.Create(u)
	}

	count, _ := userRepo.Count()
	fmt.Printf("✓ Total users in system: %d\n", count)

	// ===== 5. Session Management =====
	fmt.Println("\n=== Session Management ===")

	sessionRepo := memory.NewSessionRepository()

	// Create session
	newSession := &session.Session{
		UserID:    newUser.ID,
		Token:     "session-token-1234567890abcdef",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err = sessionRepo.Create(newSession)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	fmt.Printf("✓ Created session: ID=%s, Token=%s\n", newSession.ID[:8]+"...", newSession.Token[:20]+"...")

	// Find session by token
	foundSession, err := sessionRepo.FindByToken(newSession.Token)
	if err != nil {
		log.Fatalf("Failed to find session: %v", err)
	}
	fmt.Printf("✓ Found session: User=%s, Expires=%v\n", foundSession.UserID[:8]+"...", foundSession.ExpiresAt.Format("2006-01-02 15:04:05"))

	// Find sessions by user
	userSessions, _ := sessionRepo.FindByUserID(newUser.ID)
	fmt.Printf("✓ User has %d session(s)\n", len(userSessions))

	// Check if session expired
	fmt.Printf("✓ Session expired: %v\n", foundSession.IsExpired())

	// ===== 6. Validation Examples =====
	fmt.Println("\n=== Validation Examples ===")

	// Valid user creation request
	validReq := &user.CreateUserRequest{
		Name:  "Jane Doe",
		Email: "jane@example.com",
	}
	err = user.ValidateCreateUserRequest(validReq)
	fmt.Printf("✓ Valid user creation request: %v\n", err == nil)

	// Invalid email
	invalidEmailReq := &user.CreateUserRequest{
		Name:  "Test User",
		Email: "invalid-email",
	}
	err = user.ValidateCreateUserRequest(invalidEmailReq)
	fmt.Printf("✓ Invalid email detected: %v\n", err != nil)

	// Valid session creation request
	validSessionReq := &session.CreateSessionRequest{
		UserID:    newUser.ID,
		Token:     "valid-session-token-abc",
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	err = session.ValidateCreateSessionRequest(validSessionReq)
	fmt.Printf("✓ Valid session creation request: %v\n", err == nil)

	fmt.Println("\n✅ All examples completed successfully!")
}
