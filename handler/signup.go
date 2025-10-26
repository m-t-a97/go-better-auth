package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/domain/user"
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
	Token string     `json:"token"`
	User  *user.User `json:"user"`
}

// SignUpHandler handles POST /auth/signup
func SignUpHandler(service *auth.Service) http.HandlerFunc {
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
		resp, err := service.SignUp(r.Context(), &auth.SignUpRequest{
			Email:    req.Email,
			Password: req.Password,
			Name:     req.Name,
		})
		if err != nil {
			// Map error to HTTP status
			errMsg := err.Error()
			if errMsg == "sign up is disabled" {
				ErrorResponse(w, http.StatusForbidden, "sign up is disabled")
			} else if errMsg == "user with this email already exists" {
				ErrorResponse(w, http.StatusConflict, "email already registered")
			} else if strings.HasPrefix(errMsg, "invalid request:") {
				ErrorResponse(w, http.StatusBadRequest, errMsg)
			} else {
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		httpResp := SignUpResponse{
			Token: resp.Session.Token,
			User:  resp.User,
		}

		SuccessResponse(w, http.StatusCreated, httpResp)
	}
}
