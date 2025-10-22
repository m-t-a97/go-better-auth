package handler

import (
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// AuthHandler implements http.Handler for all auth endpoints
type AuthHandler struct {
	service *auth.Service
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(service *auth.Service) http.Handler {
	return &AuthHandler{
		service: service,
	}
}

// ServeHTTP dispatches requests to appropriate handlers
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	// Extract the endpoint (everything after /auth/)
	endpoint := ""
	if after, ok := strings.CutPrefix(path, "/auth/"); ok {
		endpoint = after
	}

	switch method {
	case "GET":
		switch endpoint {
		case "validate":
			ValidateSessionHandler(h.service)(w, r)
		case "me":
			GetProfileHandler(h.service)(w, r)
		default:
			http.NotFound(w, r)
		}
	case "POST":
		switch endpoint {
		case "sign-up/email":
			SignUpHandler(h.service)(w, r)
		case "sign-in/email":
			SignInHandler(h.service)(w, r)
		case "sign-out":
			SignOutHandler(h.service)(w, r)
		case "validate":
			ValidateSessionHandler(h.service)(w, r)
		case "refresh":
			RefreshTokenHandler(h.service)(w, r)
		case "password-reset/request":
			RequestPasswordResetHandler(h.service)(w, r)
		case "password-reset/confirm":
			ResetPasswordHandler(h.service)(w, r)
		case "email-verification/request":
			RequestEmailVerificationHandler(h.service)(w, r)
		case "email-verification/confirm":
			VerifyEmailHandler(h.service)(w, r)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}
