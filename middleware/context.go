package middleware

import (
	"context"
	"fmt"
)

// Context keys for storing values in request context
type ContextKey string

const (
	// UserIDKey is the context key for storing the authenticated user ID
	UserIDKey ContextKey = "user_id"

	// SessionTokenKey is the context key for storing the session token
	SessionTokenKey ContextKey = "session_token"

	// SessionKey is the context key for storing the full session object
	SessionKey ContextKey = "session"
)

// GetUserID retrieves the user ID from the request context
func GetUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(UserIDKey).(string)
	if !ok {
		return "", fmt.Errorf("user ID not found in context")
	}
	if userID == "" {
		return "", fmt.Errorf("user ID is empty")
	}
	return userID, nil
}

// SetUserID sets the user ID in the request context
func SetUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// GetSessionToken retrieves the session token from the request context
func GetSessionToken(ctx context.Context) (string, error) {
	token, ok := ctx.Value(SessionTokenKey).(string)
	if !ok {
		return "", fmt.Errorf("session token not found in context")
	}
	if token == "" {
		return "", fmt.Errorf("session token is empty")
	}
	return token, nil
}

// SetSessionToken sets the session token in the request context
func SetSessionToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, SessionTokenKey, token)
}

// MustGetUserID retrieves the user ID from context and panics if not found
// Use this in handlers that are protected by AuthMiddleware
func MustGetUserID(ctx context.Context) (string, error) {
	userID, err := GetUserID(ctx)
	if err != nil {
		return "", fmt.Errorf("user ID not found in context - ensure AuthMiddleware is applied")
	}
	return userID, nil
}

// MustGetSessionToken retrieves the session token from context and panics if not found
func MustGetSessionToken(ctx context.Context) (string, error) {
	token, err := GetSessionToken(ctx)
	if err != nil {
		return "", fmt.Errorf("session token not found in context - ensure AuthMiddleware is applied")
	}
	return token, nil
}
