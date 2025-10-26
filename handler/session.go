package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// ValidateSessionRequest is the HTTP request for validating a session
type ValidateSessionRequest struct {
	Token string `json:"token"`
}

// ValidateSessionResponse is the HTTP response for validating a session
type ValidateSessionResponse struct {
	Valid     bool      `json:"valid"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ValidateSessionHandler handles GET /auth/validate
func ValidateSessionHandler(s *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Try to get token from Authorization header first
		authHeader := r.Header.Get("Authorization")
		var token string

		if authHeader != "" {
			// Expected format: "Bearer <token>"
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				token = parts[1]
			}
		}

		if token == "" {
			ErrorResponse(w, http.StatusBadRequest, "session token required")
			return
		}

		// Call use case
		resp, err := s.ValidateSession(&auth.ValidateSessionRequest{
			SessionToken: token,
		})
		if err != nil {
			ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			return
		}

		if !resp.Valid {
			ErrorResponse(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}

		// Build response
		httpResp := ValidateSessionResponse{
			Valid:     resp.Valid,
			UserID:    resp.Session.UserID,
			ExpiresAt: resp.Session.ExpiresAt,
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}

// RefreshTokenRequest is the HTTP request for refreshing a token
type RefreshTokenRequest struct {
	Token string `json:"token"`
}

// RefreshTokenResponse is the HTTP response for refreshing a token
type RefreshTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RefreshTokenHandler handles POST /auth/refresh
func RefreshTokenHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Extract IP address and user agent from request
		ipAddress := r.RemoteAddr
		userAgent := r.Header.Get("User-Agent")

		// Call use case
		resp, err := svc.RefreshToken(&auth.RefreshTokenRequest{
			SessionToken: req.Token,
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "session token is required":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case "session not found":
				ErrorResponse(w, http.StatusUnauthorized, "invalid session")
			case "session has expired":
				ErrorResponse(w, http.StatusUnauthorized, "session expired")
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := RefreshTokenResponse{
			Token:     resp.Session.Token,
			ExpiresAt: resp.Session.ExpiresAt,
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}
