package handler

import (
	"net/http"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// Router registers all authentication handlers
type Router struct {
	service *auth.Service
}

// NewRouter creates a new router with the given service
func NewRouter(service *auth.Service) *Router {
	return &Router{
		service: service,
	}
}

// RegisterRoutes registers all handlers to the given mux
func (r *Router) RegisterRoutes(mux *http.ServeMux) {
	// Authentication endpoints
	mux.HandleFunc("POST /auth/signup", SignUpHandler(r.service))
	mux.HandleFunc("POST /auth/signin", SignInHandler(r.service))
	mux.HandleFunc("POST /auth/signout", SignOutHandler(r.service))

	// Session endpoints
	mux.HandleFunc("GET /auth/validate", ValidateSessionHandler(r.service))
	mux.HandleFunc("POST /auth/validate", ValidateSessionHandler(r.service))
	mux.HandleFunc("POST /auth/refresh", RefreshTokenHandler(r.service))

	// Password reset endpoints
	mux.HandleFunc("POST /auth/password-reset/request", RequestPasswordResetHandler(r.service))
	mux.HandleFunc("POST /auth/password-reset/confirm", ResetPasswordHandler(r.service))

	// Email verification endpoints
	mux.HandleFunc("POST /auth/email-verification/request", RequestEmailVerificationHandler(r.service))
	mux.HandleFunc("POST /auth/email-verification/confirm", VerifyEmailHandler(r.service))

	// Profile endpoints
	mux.HandleFunc("GET /auth/me", GetProfileHandler(r.service))
	mux.HandleFunc("POST /auth/me", GetProfileHandler(r.service))
}
