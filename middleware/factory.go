package middleware

import (
	"log/slog"
	"net/http"

	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// AuthMiddlewareFactory provides functions to create initialized middleware instances
// This is useful for applications that want to defer middleware creation until after
// the library has been initialized, particularly when using dependency injection.
type AuthMiddlewareFactory struct {
	service    *auth.Service
	cookieName string
	logger     *slog.Logger
}

// NewAuthMiddlewareFactory creates a new factory with an auth service and logger
func NewAuthMiddlewareFactory(service *auth.Service, logger *slog.Logger) *AuthMiddlewareFactory {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthMiddlewareFactory{
		service:    service,
		cookieName: "session_token",
		logger:     logger,
	}
}

// AuthHandler returns the auth middleware's Handler method bound to this factory's service
// This is convenient for use with frameworks that expect http.Handler wrappers.
func (f *AuthMiddlewareFactory) AuthHandler(next http.Handler) http.Handler {
	mw := NewAuthMiddleware(f.service)
	return mw.Handler(next)
}

// AuthHandlerFunc returns the auth middleware's HandlerFunc method bound to this factory's service
// This is convenient for use with frameworks that expect http.HandlerFunc wrappers.
func (f *AuthMiddlewareFactory) AuthHandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	mw := NewAuthMiddleware(f.service)
	return mw.HandlerFunc(next)
}

// OptionalAuthHandler returns the optional auth middleware's Handler method bound to this factory's service
// This is convenient for use with frameworks that expect http.Handler wrappers.
func (f *AuthMiddlewareFactory) OptionalAuthHandler(next http.Handler) http.Handler {
	mw := NewOptionalAuthMiddleware(f.service)
	return mw.Handler(next)
}

// OptionalAuthHandlerFunc returns the optional auth middleware's HandlerFunc method bound to this factory's service
// This is convenient for use with frameworks that expect http.HandlerFunc wrappers.
func (f *AuthMiddlewareFactory) OptionalAuthHandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	mw := NewOptionalAuthMiddleware(f.service)
	return mw.HandlerFunc(next)
}

// WithCookieName sets a custom cookie name for future middleware creations
func (f *AuthMiddlewareFactory) WithCookieName(cookieName string) *AuthMiddlewareFactory {
	f.cookieName = cookieName
	return f
}
