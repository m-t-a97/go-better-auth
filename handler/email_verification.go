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
		resp, err := svc.RequestEmailVerification(&auth.RequestEmailVerificationRequest{
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

// VerifyEmailRequest is the HTTP request for verifying an email
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmailResponse is the HTTP response for verifying an email
type VerifyEmailResponse struct {
	Message string `json:"message"`
}

// VerifyEmailHandler handles POST /auth/email-verification/confirm
func VerifyEmailHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		_, err := svc.VerifyEmail(&auth.VerifyEmailRequest{
			VerificationToken: req.Token,
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

		// Build response
		httpResp := VerifyEmailResponse{
			Message: "email verified successfully",
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}
