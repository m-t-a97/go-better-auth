package auth

import (
	"fmt"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
)

// ValidateSessionRequest contains the request data for validating a session
type ValidateSessionRequest struct {
	SessionToken string `json:"session_token"`
}

// ValidateSessionResponse contains the response data for validating a session
type ValidateSessionResponse struct {
	Session *session.Session `json:"session"`
	Valid   bool             `json:"valid"`
}

// ValidateSession is the use case for validating a user's session
func (s *Service) ValidateSession(req *ValidateSessionRequest) (*ValidateSessionResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("validate session request cannot be nil")
	}

	if req.SessionToken == "" {
		return nil, fmt.Errorf("session token is required")
	}

	// Find session by token
	sess, err := s.sessionRepo.FindByToken(req.SessionToken)
	if err != nil {
		// Session not found is not an error for validation, just return invalid
		return &ValidateSessionResponse{
			Session: nil,
			Valid:   false,
		}, nil
	}

	if sess == nil {
		return &ValidateSessionResponse{
			Session: nil,
			Valid:   false,
		}, nil
	}

	// Check if session has expired
	if sess.IsExpired() {
		return &ValidateSessionResponse{
			Session: sess,
			Valid:   false,
		}, nil
	}

	return &ValidateSessionResponse{
		Session: sess,
		Valid:   true,
	}, nil
}
