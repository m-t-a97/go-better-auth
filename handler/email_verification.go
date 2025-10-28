package handler

import (
	"encoding/json"
	"net/http"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// SendEmailVerificationRequest is the HTTP request for requesting email verification
type SendEmailVerificationRequest struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callback_url,omitempty"`
}

// SendEmailVerificationResponse is the HTTP response for requesting email verification
type SendEmailVerificationResponse struct {
	Status bool `json:"status"`
}

// SendEmailVerificationHandler handles POST /auth/send-email-verification
func SendEmailVerificationHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req SendEmailVerificationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		resp, err := svc.SendEmailVerification(r.Context(), &auth.SendEmailVerificationRequest{
			Email:       req.Email,
			CallbackURL: req.CallbackURL,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "email is required":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			default:
				ErrorResponse(w, http.StatusInternalServerError, err.Error())
			}
			return
		}

		SuccessResponse(w, http.StatusOK, &SendEmailVerificationResponse{
			Status: resp.Status,
		})
	}
}

// VerifyEmailResponse is the HTTP response for verifying email
type VerifyEmailResponse struct {
	Status bool `json:"status"`
}

// VerifyEmailHandler handles GET /auth/verify-email?token={token}&callbackURL={callbackURL} OR POST /auth/verify-email
// This unified handler verifies all types of verification tokens:
// - Email verification
// - Email change confirmation
// - Password reset confirmation
// It extracts the token from query parameters or POST body, validates it, and redirects to a success page or returns a response.
func VerifyEmailHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token string

		// Handle both GET and POST methods
		switch r.Method {
		case http.MethodGet:
			// Extract token from query parameters
			token = r.URL.Query().Get("token")
			if token == "" {
				ErrorResponse(w, http.StatusBadRequest, "verification token is required")
				return
			}
		case http.MethodPost:
			// Extract token from JSON body
			var req struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				ErrorResponse(w, http.StatusBadRequest, "invalid request body")
				return
			}
			token = req.Token
			if token == "" {
				ErrorResponse(w, http.StatusBadRequest, "verification token is required")
				return
			}
		default:
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Call unified use case to verify email
		resp, err := svc.VerifyEmail(r.Context(), &auth.VerifyEmailRequest{
			VerificationToken: token,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "verification token is required":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case "invalid verification token":
				ErrorResponse(w, http.StatusUnauthorized, "invalid or expired verification token")
			case "verification token has expired":
				ErrorResponse(w, http.StatusUnauthorized, "verification token has expired")
			case "user not found":
				ErrorResponse(w, http.StatusNotFound, "user not found")
			case "email is already in use":
				ErrorResponse(w, http.StatusConflict, err.Error())
			default:
				ErrorResponse(w, http.StatusInternalServerError, err.Error())
			}
			return
		}

		// Extract optional callbackURL for GET requests to support redirects
		if r.Method == http.MethodGet {
			callbackURL := r.URL.Query().Get("callbackURL")
			if callbackURL != "" {
				http.Redirect(w, r, callbackURL, http.StatusSeeOther)
				return
			}
		}

		SuccessResponse(w, http.StatusOK, &VerifyEmailResponse{
			Status: resp.Status,
		})
	}
}
