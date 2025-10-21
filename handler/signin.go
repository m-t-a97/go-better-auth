package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// SignInRequest is the HTTP request for user signin
type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignInResponse is the HTTP response for user signin
type SignInResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    string    `json:"user_id"`
}

// SignInHandler handles POST /auth/signin
func SignInHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req SignInRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Extract IP address and user agent from request
		ipAddress := r.RemoteAddr
		userAgent := r.Header.Get("User-Agent")

		// Call use case
		resp, err := svc.SignIn(&auth.SignInRequest{
			Email:     req.Email,
			Password:  req.Password,
			IPAddress: ipAddress,
			UserAgent: userAgent,
		})
		if err != nil {
			// Map error to HTTP status
			errMsg := err.Error()
			switch errMsg {
			case "invalid request":
				ErrorResponse(w, http.StatusBadRequest, errMsg)
			case "user not found":
				ErrorResponse(w, http.StatusUnauthorized, "invalid email or password")
			case "account not found":
				ErrorResponse(w, http.StatusUnauthorized, "invalid email or password")
			default:
				// Check if it contains password-related keywords
				if strings.Contains(errMsg, "password") || strings.Contains(errMsg, "verify") {
					ErrorResponse(w, http.StatusUnauthorized, "invalid email or password")
				} else {
					ErrorResponse(w, http.StatusInternalServerError, "internal server error")
				}
			}
			return
		}

		// Build response
		httpResp := SignInResponse{
			Token:     resp.Session.Token,
			ExpiresAt: resp.Session.ExpiresAt,
			UserID:    resp.Session.UserID,
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}
