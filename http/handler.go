package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/domain"
	"github.com/m-t-a97/go-better-auth/usecase"
)

// AuthHandler handles authentication endpoints using standard library http.Handler
type AuthHandler struct {
	authUseCase    *usecase.AuthUseCase
	oauthUseCase   *usecase.OAuthUseCase
	mfaUseCase     *usecase.MFAUseCase
	baseURL        string
	trustedOrigins []string
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(
	authUseCase *usecase.AuthUseCase,
	oauthUseCase *usecase.OAuthUseCase,
	mfaUseCase *usecase.MFAUseCase,
	baseURL string,
	trustedOrigins []string,
) *AuthHandler {
	return &AuthHandler{
		authUseCase:    authUseCase,
		oauthUseCase:   oauthUseCase,
		mfaUseCase:     mfaUseCase,
		baseURL:        baseURL,
		trustedOrigins: trustedOrigins,
	}
}

// ServeHTTP implements http.Handler interface for routing
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Content-Type", "application/json")

	// Extract the endpoint name from the URL path by splitting on /auth/
	path := r.URL.Path
	parts := strings.SplitN(path, "/auth/", 2)
	var endpoint string
	if len(parts) == 2 {
		endpoint = strings.Trim(parts[1], "/")
	} else {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	method := strings.ToUpper(r.Method)

	// Route to appropriate handler
	switch method {
	case http.MethodPost:
		switch endpoint {
		case "sign-up/email":
			h.signUpEmail(w, r)
		case "sign-in/email":
			h.signInEmail(w, r)
		case "sign-out":
			h.signOut(w, r)
		case "send-verification-email":
			h.sendVerificationEmail(w, r)
		case "verify-email":
			h.verifyEmail(w, r)
		case "request-password-reset":
			h.requestPasswordReset(w, r)
		case "reset-password":
			h.resetPassword(w, r)
		case "change-password":
			h.changePassword(w, r)
		case "enable-mfa":
			h.enableMFA(w, r)
		case "disable-mfa":
			h.disableMFA(w, r)
		case "verify-mfa":
			h.verifyMFA(w, r)
		default:
			http.Error(w, "Not found", http.StatusNotFound)
		}

	case http.MethodGet:
		switch endpoint {
		case "session":
			h.getSession(w, r)
		default:
			// Handle OAuth callback with dynamic provider
			if strings.HasPrefix(endpoint, "oauth/") {
				parts := strings.Split(endpoint, "/")
				if len(parts) >= 2 {
					h.oauthAuthorize(w, r, parts[1])
				} else {
					http.Error(w, "Provider required", http.StatusBadRequest)
				}
			} else {
				http.Error(w, "Not found", http.StatusNotFound)
			}
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// signUpEmail handles POST /auth/sign-up/email
func (h *AuthHandler) signUpEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", "invalid_request")
		return
	}

	output, err := h.authUseCase.SignUpEmail(r.Context(), &domain.SignUpEmailInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Set-Cookie", h.setSessionCookie(output.Session.Token))
	writeJSON(w, http.StatusCreated, output)
}

// signInEmail handles POST /auth/sign-in/email
func (h *AuthHandler) signInEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", "invalid_request")
		return
	}

	output, err := h.authUseCase.SignInEmail(r.Context(), &domain.SignInEmailInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Set-Cookie", h.setSessionCookie(output.Session.Token))
	writeJSON(w, http.StatusOK, output)
}

// signOut handles POST /auth/sign-out
func (h *AuthHandler) signOut(w http.ResponseWriter, r *http.Request) {
	token := h.getSessionToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "No session", "no_session")
		return
	}

	err := h.authUseCase.SignOut(r.Context(), token)
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Set-Cookie", h.clearSessionCookie())
	writeJSON(w, http.StatusOK, map[string]string{"message": "Signed out successfully"})
}

// getSession handles GET /auth/session
func (h *AuthHandler) getSession(w http.ResponseWriter, r *http.Request) {
	token := h.getSessionToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "No session", "no_session")
		return
	}

	session, user, err := h.authUseCase.GetSession(r.Context(), token)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":    user,
		"session": session,
	})
}

// sendVerificationEmail handles POST /auth/send-verification-email
func (h *AuthHandler) sendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", "invalid_request")
		return
	}

	err := h.authUseCase.SendVerificationEmail(r.Context(), req.Email)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Verification email sent"})
}

// verifyEmail handles POST /auth/verify-email
func (h *AuthHandler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", "invalid_request")
		return
	}

	user, err := h.authUseCase.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// requestPasswordReset handles POST /auth/request-password-reset
func (h *AuthHandler) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", "invalid_request")
		return
	}

	err := h.authUseCase.RequestPasswordReset(r.Context(), req.Email)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password reset email sent"})
}

// resetPassword handles POST /auth/reset-password
func (h *AuthHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", "invalid_request")
		return
	}

	err := h.authUseCase.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password reset successfully"})
}

// changePassword handles POST /auth/change-password
func (h *AuthHandler) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword     string `json:"currentPassword"`
		NewPassword         string `json:"newPassword"`
		RevokeOtherSessions bool   `json:"revokeOtherSessions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", "invalid_request")
		return
	}

	token := h.getSessionToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "No session", "no_session")
		return
	}

	// Get user from session
	_, user, err := h.authUseCase.GetSession(r.Context(), token)
	if err != nil {
		h.handleError(w, err)
		return
	}

	err = h.authUseCase.ChangePassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword, req.RevokeOtherSessions)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

// oauthAuthorize handles GET /auth/oauth/{provider}
func (h *AuthHandler) oauthAuthorize(w http.ResponseWriter, r *http.Request, provider string) {
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	if state == "" {
		writeError(w, http.StatusBadRequest, "State parameter required", "missing_state")
		return
	}

	authURL, err := h.oauthUseCase.GetAuthURL(provider, state, redirectURI)
	if err != nil {
		h.handleError(w, err)
		return
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// enableMFA handles POST /auth/enable-mfa - NOT IMPLEMENTED YET
func (h *AuthHandler) enableMFA(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "MFA endpoints not yet implemented", "not_implemented")
}

// disableMFA handles POST /auth/disable-mfa - NOT IMPLEMENTED YET
func (h *AuthHandler) disableMFA(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "MFA endpoints not yet implemented", "not_implemented")
}

// verifyMFA handles POST /auth/verify-mfa - NOT IMPLEMENTED YET
func (h *AuthHandler) verifyMFA(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "MFA endpoints not yet implemented", "not_implemented")
}

// Helper methods

// getSessionToken extracts the session token from cookie or Authorization header
func (h *AuthHandler) getSessionToken(r *http.Request) string {
	// Try Authorization header first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Try session cookie
	cookie, err := r.Cookie("go-better-auth.session_token")
	if err == nil {
		return cookie.Value
	}

	return ""
}

// setSessionCookie creates a session cookie
func (h *AuthHandler) setSessionCookie(token string) string {
	return "go-better-auth.session_token=" + token + "; Path=/; HttpOnly; SameSite=Strict"
}

// clearSessionCookie clears the session cookie
func (h *AuthHandler) clearSessionCookie() string {
	return "go-better-auth.session_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
}

// handleError handles domain errors and writes appropriate HTTP responses
func (h *AuthHandler) handleError(w http.ResponseWriter, err error) {
	var authErr *domain.AuthError
	if errors.As(err, &authErr) {
		writeError(w, authErr.Status, authErr.Message, authErr.Code)
		return
	}

	writeError(w, http.StatusInternalServerError, "Internal server error", "internal_error")
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error JSON response
func writeError(w http.ResponseWriter, status int, message string, code string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
