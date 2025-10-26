package handler

import (
	"encoding/json"
	"net/http"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// RequestEmailVerificationRequest is the HTTP request for requesting email verification
type RequestEmailVerificationRequest struct {
	Email string `json:"email"`
}

// RequestEmailVerificationResponse is the HTTP response for requesting email verification
type RequestEmailVerificationResponse struct {
	Message string `json:"message"`
	Token   string `json:"token"`
}

// RequestEmailVerificationHandler handles POST /auth/email-verification/request
func RequestEmailVerificationHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req RequestEmailVerificationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		resp, err := svc.RequestEmailVerification(r.Context(), &auth.RequestEmailVerificationRequest{
			Email: req.Email,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "email is required":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := RequestEmailVerificationResponse{
			Message: "verification email sent",
			Token:   resp.Verification.Token,
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}

// VerifyEmailHandler handles GET /auth/verify-email?token={token}
// This handler is called when a user clicks the verification link in the email.
// It extracts the token from the query parameters, validates it, and redirects to a success page.
func VerifyEmailHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Extract token from query parameters
		token := r.URL.Query().Get("token")
		if token == "" {
			ErrorResponse(w, http.StatusBadRequest, "verification token is required")
			return
		}

		// Call use case to verify email
		_, err := svc.VerifyEmail(&auth.VerifyEmailRequest{
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
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Get the redirect URL from config, fallback to login page
		config := svc.GetConfig()
		redirectURL := ""
		if config.EmailVerification != nil && config.EmailVerification.SuccessRedirectURL != "" {
			redirectURL = config.EmailVerification.SuccessRedirectURL
		} else if config.BaseURL != "" {
			// Default redirect to base URL
			redirectURL = config.BaseURL
		} else {
			// Fallback to root
			redirectURL = "/"
		}

		// Redirect to success page
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	}
}
