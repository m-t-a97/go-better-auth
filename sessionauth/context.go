package sessionauth

import (
	"context"
	"time"

	"github.com/m-t-a97/go-better-auth/domain"
)

type contextKey string

const (
	userContextKey    contextKey = "sessionauth:user"
	sessionContextKey contextKey = "sessionauth:session"
)

// GetUser retrieves the authenticated user from the context
// Returns nil if no user is authenticated
func GetUser(ctx context.Context) *domain.User {
	user, ok := ctx.Value(userContextKey).(*domain.User)
	if !ok {
		return nil
	}
	return user
}

// GetSession retrieves the session from the context
// Returns nil if no session is found
func GetSession(ctx context.Context) *domain.Session {
	session, ok := ctx.Value(sessionContextKey).(*domain.Session)
	if !ok {
		return nil
	}
	return session
}

// IsAuthenticated checks if a user is authenticated in the context
func IsAuthenticated(ctx context.Context) bool {
	return GetUser(ctx) != nil
}

// GetUserID retrieves the authenticated user's ID from the context
// Returns empty string if no user is authenticated
func GetUserID(ctx context.Context) string {
	user := GetUser(ctx)
	if user == nil {
		return ""
	}
	return user.ID
}

// getCurrentTime returns the current time
// This is extracted as a function to allow for testing
var getCurrentTime = time.Now
