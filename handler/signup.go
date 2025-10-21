package handler

import (
	"encoding/json"
	"net/http"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// SignUpRequest is the HTTP request for user signup
type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// SignUpResponse is the HTTP response for user signup
type SignUpResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
}

// SignUpHandler handles POST /auth/signup
func SignUpHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req SignUpRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		resp, err := svc.SignUp(&auth.SignUpRequest{
			Email:    req.Email,
			Password: req.Password,
			Name:     req.Name,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "user with this email already exists":
				ErrorResponse(w, http.StatusConflict, "email already registered")
			case "invalid request":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := SignUpResponse{
			ID:            resp.User.ID,
			Email:         resp.User.Email,
			Name:          resp.User.Name,
			EmailVerified: resp.User.EmailVerified,
		}

		SuccessResponse(w, http.StatusCreated, httpResp)
	}
}
