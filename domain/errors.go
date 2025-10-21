package domain

// AuthError represents an authentication error
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

func (e *AuthError) Error() string {
	return e.Message
}

// Common error codes
var (
	ErrInvalidCredentials = &AuthError{
		Code:    "invalid_credentials",
		Message: "Invalid email or password",
		Status:  401,
	}
	ErrUserNotFound = &AuthError{
		Code:    "user_not_found",
		Message: "User not found",
		Status:  404,
	}
	ErrUserAlreadyExists = &AuthError{
		Code:    "user_already_exists",
		Message: "A user with this email already exists",
		Status:  409,
	}
	ErrInvalidToken = &AuthError{
		Code:    "invalid_token",
		Message: "Invalid or expired token",
		Status:  401,
	}
	ErrSessionExpired = &AuthError{
		Code:    "session_expired",
		Message: "Session has expired",
		Status:  401,
	}
	ErrSessionNotFound = &AuthError{
		Code:    "session_not_found",
		Message: "Session not found",
		Status:  401,
	}
	ErrEmailNotVerified = &AuthError{
		Code:    "email_not_verified",
		Message: "Email address not verified",
		Status:  403,
	}
	ErrInvalidRequest = &AuthError{
		Code:    "invalid_request",
		Message: "Invalid request parameters",
		Status:  400,
	}
	ErrNotFound = &AuthError{
		Code:    "not_found",
		Message: "Resource not found",
		Status:  404,
	}
)
