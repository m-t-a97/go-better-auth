package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
	"github.com/GoBetterAuth/go-better-auth/repository/memory"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

func setupTestService() *auth.Service {
	config := &domain.Config{}
	config.ApplyDefaults()

	return auth.NewService(
		config,
		memory.NewUserRepository(),
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		memory.NewVerificationRepository(),
	)
}

func TestSignUpHandler_Valid(t *testing.T) {
	service := setupTestService()
	handler := SignUpHandler(service)

	req := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if !resp.Success {
		t.Error("Expected success response")
	}

	data := resp.Data.(map[string]any)
	if data["token"] == nil {
		t.Error("Expected token in response")
	}

	user := data["user"].(map[string]interface{})
	if user["email"] != req.Email {
		t.Errorf("Expected email %s, got %v", req.Email, user["email"])
	}
}

func TestSignUpHandler_InvalidMethod(t *testing.T) {
	svc := setupTestService()
	handler := SignUpHandler(svc)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/signup", nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestSignUpHandler_InvalidBody(t *testing.T) {
	svc := setupTestService()
	handler := SignUpHandler(svc)

	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestSignUpHandler_DuplicateEmail(t *testing.T) {
	svc := setupTestService()

	// Create first user
	req1 := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body1, _ := json.Marshal(req1)
	httpReq1 := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body1))
	w1 := httptest.NewRecorder()
	SignUpHandler(svc)(w1, httpReq1)

	// Try to create second user with same email
	req2 := SignUpRequest{
		Email:    "test@example.com",
		Password: "DifferentPassword456!",
		Name:     "Another User",
	}
	body2, _ := json.Marshal(req2)
	httpReq2 := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	SignUpHandler(svc)(w2, httpReq2)

	if w2.Code != http.StatusConflict {
		t.Errorf("Expected status %d, got %d", http.StatusConflict, w2.Code)
	}
}

func TestSignInHandler_Valid(t *testing.T) {
	svc := setupTestService()

	// Sign up first
	signupReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body, _ := json.Marshal(signupReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	SignUpHandler(svc)(w, httpReq)

	// Now sign in
	signinReq := SignInRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
	}
	signinBody, _ := json.Marshal(signinReq)
	signinHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signin", bytes.NewReader(signinBody))
	signinW := httptest.NewRecorder()

	SignInHandler(svc)(signinW, signinHttpReq)

	if signinW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, signinW.Code)
	}

	var resp Response
	json.NewDecoder(signinW.Body).Decode(&resp)

	if !resp.Success {
		t.Error("Expected success response")
	}
}

func TestSignInHandler_InvalidPassword(t *testing.T) {
	svc := setupTestService()

	// Sign up first
	signupReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body, _ := json.Marshal(signupReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	SignUpHandler(svc)(w, httpReq)

	// Try to sign in with wrong password
	signinReq := SignInRequest{
		Email:    "test@example.com",
		Password: "WrongPassword456!",
	}
	signinBody, _ := json.Marshal(signinReq)
	signinHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signin", bytes.NewReader(signinBody))
	signinW := httptest.NewRecorder()

	SignInHandler(svc)(signinW, signinHttpReq)

	if signinW.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, signinW.Code)
	}
}

func TestSignOutHandler_Valid(t *testing.T) {
	svc := setupTestService()

	// Sign up and sign in
	signupReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body, _ := json.Marshal(signupReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	SignUpHandler(svc)(w, httpReq)

	signinReq := SignInRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
	}
	signinBody, _ := json.Marshal(signinReq)
	signinHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signin", bytes.NewReader(signinBody))
	signinW := httptest.NewRecorder()

	SignInHandler(svc)(signinW, signinHttpReq)

	var signinResp Response
	json.NewDecoder(signinW.Body).Decode(&signinResp)
	signinData := signinResp.Data.(map[string]interface{})
	token := signinData["token"].(string)

	// Sign out
	signoutReq := SignOutRequest{
		Token: token,
	}
	signoutBody, _ := json.Marshal(signoutReq)
	signoutHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signout", bytes.NewReader(signoutBody))
	signoutW := httptest.NewRecorder()

	SignOutHandler(svc)(signoutW, signoutHttpReq)

	if signoutW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, signoutW.Code)
	}
}

func TestValidateSessionHandler_Valid(t *testing.T) {
	svc := setupTestService()

	// Sign up and sign in to get token
	signupReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body, _ := json.Marshal(signupReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	SignUpHandler(svc)(w, httpReq)

	signinReq := SignInRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
	}
	signinBody, _ := json.Marshal(signinReq)
	signinHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signin", bytes.NewReader(signinBody))
	signinW := httptest.NewRecorder()

	SignInHandler(svc)(signinW, signinHttpReq)

	var signinResp Response
	json.NewDecoder(signinW.Body).Decode(&signinResp)
	signinData := signinResp.Data.(map[string]interface{})
	token := signinData["token"].(string)

	// Validate session
	validateReq := ValidateSessionRequest{
		Token: token,
	}
	validateBody, _ := json.Marshal(validateReq)
	validateHttpReq := httptest.NewRequest(http.MethodPost, "/auth/validate", bytes.NewReader(validateBody))
	validateHttpReq.Header.Set("Authorization", "Bearer "+token)
	validateW := httptest.NewRecorder()

	ValidateSessionHandler(svc)(validateW, validateHttpReq)

	if validateW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, validateW.Code)
	}

	var validateResp Response
	json.NewDecoder(validateW.Body).Decode(&validateResp)

	if !validateResp.Success {
		t.Error("Expected success response")
	}
}

func TestValidateSessionHandler_InvalidToken(t *testing.T) {
	svc := setupTestService()

	validateHttpReq := httptest.NewRequest(http.MethodPost, "/auth/validate", nil)
	validateHttpReq.Header.Set("Authorization", "Bearer invalid-token")
	validateW := httptest.NewRecorder()

	ValidateSessionHandler(svc)(validateW, validateHttpReq)

	if validateW.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, validateW.Code)
	}
}

func TestResponseEnvelope_Success(t *testing.T) {
	w := httptest.NewRecorder()
	SuccessResponse(w, http.StatusOK, map[string]string{"key": "value"})

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if !resp.Success {
		t.Error("Expected success = true")
	}

	if resp.Error != "" {
		t.Errorf("Expected no error, got %s", resp.Error)
	}
}

func TestResponseEnvelope_Error(t *testing.T) {
	w := httptest.NewRecorder()
	ErrorResponse(w, http.StatusBadRequest, "bad request")

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Success {
		t.Error("Expected success = false")
	}

	if resp.Error != "bad request" {
		t.Errorf("Expected error 'bad request', got %s", resp.Error)
	}
}

// Email Verification Tests

func TestVerifyEmailGetHandler_ValidToken(t *testing.T) {
	// Setup
	userRepo := memory.NewUserRepository()
	verificationRepo := memory.NewVerificationRepository()

	// Create a user
	testUser := &user.User{
		ID:            "test-user-id",
		Email:         "verify@example.com",
		EmailVerified: false,
		Name:          "Test User",
	}
	userRepo.Create(testUser)

	// Create verification token
	verificationToken := "valid-token-12345"
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      crypto.HashVerificationToken(verificationToken),
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
	}
	verificationRepo.Create(v)

	config := &domain.Config{}
	config.ApplyDefaults()
	config.BaseURL = "https://example.com"

	service := auth.NewService(
		config,
		userRepo,
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	handler := VerifyEmailHandler(service)

	// Make request
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+verificationToken, nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	// Verify redirect
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify user email is now verified
	verifiedUser, _ := userRepo.FindByID(testUser.ID)
	if !verifiedUser.EmailVerified {
		t.Error("Expected user email to be verified")
	}

	// Verify token is deleted
	_, err := verificationRepo.FindByHashedToken(verificationToken)
	if err == nil {
		t.Error("Expected verification token to be deleted")
	}
}

func TestVerifyEmailGetHandler_MissingToken(t *testing.T) {
	service := setupTestService()
	handler := VerifyEmailHandler(service)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email", nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestVerifyEmailGetHandler_InvalidToken(t *testing.T) {
	service := setupTestService()
	handler := VerifyEmailHandler(service)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token=invalid-token", nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	// Invalid token should return 401 Unauthorized
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 401 or 500, got %d", w.Code)
	}
}

func TestVerifyEmailGetHandler_ExpiredToken(t *testing.T) {
	// Setup
	userRepo := memory.NewUserRepository()
	verificationRepo := memory.NewVerificationRepository()

	// Create a user
	testUser := &user.User{
		ID:            "test-user-id",
		Email:         "verify@example.com",
		EmailVerified: false,
		Name:          "Test User",
	}
	userRepo.Create(testUser)

	// Create expired verification token
	verificationToken := "expired-token-12345"
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      crypto.HashVerificationToken(verificationToken),
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		CreatedAt:  time.Now().Add(-2 * time.Hour),
	}
	verificationRepo.Create(v)

	config := &domain.Config{}
	config.ApplyDefaults()

	service := auth.NewService(
		config,
		userRepo,
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	handler := VerifyEmailHandler(service)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+verificationToken, nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestVerifyEmailGetHandler_InvalidMethod(t *testing.T) {
	service := setupTestService()
	handler := VerifyEmailHandler(service)

	// Test with invalid method (PUT)
	httpReq := httptest.NewRequest(http.MethodPut, "/auth/verify-email", nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestVerifyEmailGetHandler_CustomRedirectURL(t *testing.T) {
	// Setup
	userRepo := memory.NewUserRepository()
	verificationRepo := memory.NewVerificationRepository()

	// Create a user
	testUser := &user.User{
		ID:            "test-user-id",
		Email:         "verify@example.com",
		EmailVerified: false,
		Name:          "Test User",
	}
	userRepo.Create(testUser)

	// Create verification token
	verificationToken := "valid-token-12345"
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      crypto.HashVerificationToken(verificationToken),
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
	}
	verificationRepo.Create(v)

	config := &domain.Config{}
	config.ApplyDefaults()
	config.BaseURL = "https://example.com"
	config.EmailVerification = &domain.EmailVerificationConfig{
		ExpiresIn:             24 * time.Hour,
		SendVerificationEmail: nil,
	}

	service := auth.NewService(
		config,
		userRepo,
		memory.NewSessionRepository(),
		memory.NewAccountRepository(),
		verificationRepo,
	)

	handler := VerifyEmailHandler(service)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+verificationToken+"&callbackURL=https://example.com/login?verified=true", nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusSeeOther {
		t.Errorf("Expected status %d, got %d", http.StatusSeeOther, w.Code)
	}

	location := w.Header().Get("Location")
	parsedLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Expected redirect URL to be valid but got error: %v", err)
	}

	if parsedLocation.Scheme != "https" || parsedLocation.Host != "example.com" || parsedLocation.Path != "/login" {
		t.Fatalf("Unexpected redirect target: %s", location)
	}

	query := parsedLocation.Query()
	if query.Get("verified") != "true" {
		t.Fatalf("Expected verified query param to be preserved, got %s", query.Get("verified"))
	}
	if query.Get("token") != verificationToken {
		t.Fatalf("Expected token query param to be appended, got %s", query.Get("token"))
	}
	if query.Get("type") != string(verification.TypeEmailVerification) {
		t.Fatalf("Expected type query param to be appended, got %s", query.Get("type"))
	}
}
