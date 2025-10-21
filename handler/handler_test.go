package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/repository/memory"
	"github.com/m-t-a97/go-better-auth/usecase/auth"
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
	svc := setupTestService()
	handler := SignUpHandler(svc)

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

	data := resp.Data.(map[string]interface{})
	if data["email"] != req.Email {
		t.Errorf("Expected email %s, got %v", req.Email, data["email"])
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

	validateReq := ValidateSessionRequest{
		Token: "invalid-token",
	}
	validateBody, _ := json.Marshal(validateReq)
	validateHttpReq := httptest.NewRequest(http.MethodPost, "/auth/validate", bytes.NewReader(validateBody))
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

	if resp.Code != http.StatusOK {
		t.Errorf("Expected code %d, got %d", http.StatusOK, resp.Code)
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

	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected code %d, got %d", http.StatusBadRequest, resp.Code)
	}

	if resp.Error != "bad request" {
		t.Errorf("Expected error 'bad request', got %s", resp.Error)
	}
}
