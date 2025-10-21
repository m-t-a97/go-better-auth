package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// GetProfileRequest is the HTTP request for getting a user profile
type GetProfileRequest struct {
	UserID string `json:"user_id"`
}

// GetProfileResponse is the HTTP response for getting a user profile
type GetProfileResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Image         string `json:"image,omitempty"`
}

// GetProfileHandler handles GET /auth/me
func GetProfileHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Try to extract user ID from Authorization header (Bearer token)
		// In a real app, you'd validate the token and extract the UserID from it
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			ErrorResponse(w, http.StatusBadRequest, "authorization header required")
			return
		}

		// Try to get user ID from request body for POST
		var userID string
		if r.Method == http.MethodPost {
			var req GetProfileRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.UserID != "" {
				userID = req.UserID
			}
		}

		// If no user ID yet, try to extract from Authorization header
		// This is a simplified approach - in production, validate the token
		if userID == "" {
			// For demo purposes, we'll expect user ID to be in query params or require ValidateSession first
			userID = r.URL.Query().Get("user_id")
		}

		if userID == "" {
			// Try to validate session from Authorization header and get user ID
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				token := parts[1]
				// Validate session to get user ID
				resp, err := svc.ValidateSession(&auth.ValidateSessionRequest{
					SessionToken: token,
				})
				if err != nil || !resp.Valid {
					ErrorResponse(w, http.StatusUnauthorized, "invalid session")
					return
				}
				userID = resp.Session.UserID
			} else {
				ErrorResponse(w, http.StatusBadRequest, "user ID required")
				return
			}
		}

		// Call use case
		resp, err := svc.GetProfile(&auth.GetProfileRequest{
			UserID: userID,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "user ID is required":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case "user not found":
				ErrorResponse(w, http.StatusNotFound, "user not found")
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := GetProfileResponse{
			ID:            resp.User.ID,
			Email:         resp.User.Email,
			Name:          resp.User.Name,
			EmailVerified: resp.User.EmailVerified,
		}
		if resp.User.Image != nil {
			httpResp.Image = *resp.User.Image
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}
