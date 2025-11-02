package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

// SignOutRequest is the HTTP request for user signout
type SignOutRequest struct {
	Token string `json:"token"`
}

// SignOutHandler handles POST /auth/signout
func SignOutHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
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

		// If no token in header, try request body
		if token == "" {
			var req SignOutRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Token != "" {
				token = req.Token
			}
		}

		if token == "" {
			ErrorResponse(w, http.StatusBadRequest, "session token required")
			return
		}

		// Call use case
		err := svc.SignOut(&auth.SignOutRequest{
			SessionToken: token,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "session not found":
				ErrorResponse(w, http.StatusUnauthorized, "invalid session")
			default:
				ErrorResponse(w, http.StatusInternalServerError, err.Error())
			}
			return
		}

		SuccessResponse(w, http.StatusOK, map[string]string{
			"message": "signed out successfully",
		})
	}
}
