package handler

import (
	"encoding/json"
	"net/http"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// RequestPasswordResetRequest is the HTTP request for requesting a password reset
type RequestPasswordResetRequest struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callback_url,omitempty"`
}

// RequestPasswordResetResponse is the HTTP response for requesting a password reset
type RequestPasswordResetResponse struct {
	Message string `json:"message"`
}

// SendPasswordResetHandler handles POST /auth/password-reset
func SendPasswordResetHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req RequestPasswordResetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		_, err := svc.RequestPasswordReset(r.Context(), &auth.RequestPasswordResetRequest{
			Email:       req.Email,
			CallbackURL: req.CallbackURL,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "email is required":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case "user not found":
				// Don't reveal if user exists for security
				SuccessResponse(w, http.StatusOK, RequestPasswordResetResponse{
					Message: "if email exists, a password reset link has been sent",
				})
				return
			default:
				ErrorResponse(w, http.StatusInternalServerError, err.Error())
			}
			return
		}

		// Build response
		SuccessResponse(w, http.StatusOK, RequestPasswordResetResponse{
			Message: "if email exists, a password reset link has been sent",
		})
	}
}

// ResetPasswordRequest is the HTTP request for resetting a password
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ResetPasswordResponse is the HTTP response for resetting a password
type ResetPasswordResponse struct {
	Message string `json:"message"`
}

// ResetPasswordHandler handles POST /auth/reset-password
func ResetPasswordHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		_, err := svc.ResetPassword(&auth.ResetPasswordRequest{
			Token:       req.Token,
			NewPassword: req.NewPassword,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "reset token is required", "new password is required", "password must be at least 8 characters":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case "invalid reset token":
				ErrorResponse(w, http.StatusUnauthorized, "invalid or expired reset token")
			case "reset token has expired":
				ErrorResponse(w, http.StatusUnauthorized, "reset token has expired")
			default:
				ErrorResponse(w, http.StatusInternalServerError, err.Error())
			}
			return
		}

		// Build response
		httpResp := ResetPasswordResponse{
			Message: "password reset successfully",
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}
