package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// SignInRequest is the HTTP request for user signin
type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignInResponse is the HTTP response for user signin
type SignInResponse struct {
	Token string     `json:"token"`
	User  *user.User `json:"user"`
}

// SignInHandler handles POST /auth/signin
func SignInHandler(service *auth.Service) http.HandlerFunc {
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
		resp, err := service.SignIn(r.Context(), &auth.SignInRequest{
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
			case "account is temporarily locked":
				ErrorResponse(w, http.StatusTooManyRequests, "too many login attempts, try again later")
			default:
				// Check if it contains account lockout keywords
				if strings.Contains(errMsg, "locked") {
					ErrorResponse(w, http.StatusTooManyRequests, "too many login attempts, try again later")
				} else if strings.Contains(errMsg, "password") || strings.Contains(errMsg, "verify") {
					ErrorResponse(w, http.StatusUnauthorized, "invalid email or password")
				} else {
					ErrorResponse(w, http.StatusInternalServerError, "internal server error")
				}
			}
			return
		}

		// Build response
		httpResp := SignInResponse{
			Token: resp.Session.Token,
			User:  resp.User,
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}
