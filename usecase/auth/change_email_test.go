package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/m-t-a97/go-better-auth/domain/verification"
	"github.com/m-t-a97/go-better-auth/repository/memory"
)

func TestRequestChangeEmail(t *testing.T) {
	tests := []struct {
		name          string
		request       *RequestChangeEmailRequest
		setupUser     *user.User
		setupUsers    []*user.User
		expectedError string
		expectedMsg   string
	}{
		{
			name:          "nil request",
			request:       nil,
			expectedError: "request change email request cannot be nil",
		},
		{
			name: "missing user ID",
			request: &RequestChangeEmailRequest{
				NewEmail: "newemail@example.com",
			},
			expectedError: "user ID is required",
		},
		{
			name: "missing new email",
			request: &RequestChangeEmailRequest{
				UserID: "user123",
			},
			expectedError: "new email is required",
		},
		{
			name: "invalid email format",
			request: &RequestChangeEmailRequest{
				UserID:   "user123",
				NewEmail: "invalid-email",
			},
			expectedError: "invalid email: invalid email format",
		},
		{
			name: "user not found",
			request: &RequestChangeEmailRequest{
				UserID:   "nonexistent",
				NewEmail: "newemail@example.com",
			},
			expectedError: "failed to find user: user not found",
		},
		{
			name: "new email same as current email",
			request: &RequestChangeEmailRequest{
				UserID:   "user123",
				NewEmail: "user@example.com",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			expectedError: "new email is the same as current email",
		},
		{
			name: "email already in use",
			request: &RequestChangeEmailRequest{
				UserID:   "user123",
				NewEmail: "other@example.com",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "myemail@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setupUsers: []*user.User{
				{
					ID:            "user456",
					Name:          "Another User",
					Email:         "other@example.com",
					EmailVerified: true,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				},
			},
			expectedError: "email is already in use",
		},
		{
			name: "successful request",
			request: &RequestChangeEmailRequest{
				UserID:   "user123",
				NewEmail: "newemail@example.com",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userRepo := memory.NewUserRepository()
			verificationRepo := memory.NewVerificationRepository()

			// Setup user with consistent ID
			testUserID := "test-user-id"
			if tt.setupUser != nil {
				tt.setupUser.ID = testUserID
				if err := userRepo.Create(tt.setupUser); err != nil {
					t.Fatalf("failed to setup user: %v", err)
				}
				// Update request with actual user ID
				if tt.request != nil && tt.request.UserID == "user123" {
					tt.request.UserID = testUserID
				}
			}

			// Setup additional users with different IDs
			for i, u := range tt.setupUsers {
				u.ID = "test-other-user-" + string(rune(i))
				if err := userRepo.Create(u); err != nil {
					t.Fatalf("failed to setup user: %v", err)
				}
			}

			svc := &Service{
				userRepo:         userRepo,
				verificationRepo: verificationRepo,
			}

			resp, err := svc.RequestChangeEmail(tt.request)

			if tt.expectedError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %v", tt.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if resp == nil {
				t.Errorf("expected response, got nil")
				return
			}

			if resp.Verification == nil {
				t.Errorf("expected verification in response, got nil")
				return
			}

			if resp.Verification.Identifier != tt.request.NewEmail {
				t.Errorf("expected identifier %q, got %q", tt.request.NewEmail, resp.Verification.Identifier)
			}

			if resp.Verification.Type != verification.TypeEmailChange {
				t.Errorf("expected type %q, got %q", verification.TypeEmailChange, resp.Verification.Type)
			}

			if resp.Verification.Token == "" {
				t.Errorf("expected token to be generated, got empty")
			}

			if resp.Verification.ExpiresAt.Before(time.Now()) {
				t.Errorf("expected future expiry, got %v", resp.Verification.ExpiresAt)
			}
		})
	}
}

func TestConfirmChangeEmail(t *testing.T) {
	tests := []struct {
		name             string
		request          *ConfirmChangeEmailRequest
		setupUser        *user.User
		setupVerif       *verification.Verification
		expectedError    string
		expectedNewEmail string
	}{
		{
			name:          "nil request",
			request:       nil,
			expectedError: "confirm change email request cannot be nil",
		},
		{
			name: "missing user ID",
			request: &ConfirmChangeEmailRequest{
				VerificationToken: "token123",
			},
			expectedError: "user ID is required",
		},
		{
			name: "missing verification token",
			request: &ConfirmChangeEmailRequest{
				UserID: "user123",
			},
			expectedError: "verification token is required",
		},
		{
			name: "invalid verification token",
			request: &ConfirmChangeEmailRequest{
				UserID:            "user123",
				VerificationToken: "invalid",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			expectedError: "failed to find verification token: verification not found",
		},
		{
			name: "expired token",
			request: &ConfirmChangeEmailRequest{
				UserID:            "user123",
				VerificationToken: "expired_token",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setupVerif: &verification.Verification{
				Identifier: "newemail@example.com",
				Token:      "expired_token",
				Type:       verification.TypeEmailChange,
				ExpiresAt:  time.Now().Add(-1 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			expectedError: "verification token has expired",
		},
		{
			name: "user not found",
			request: &ConfirmChangeEmailRequest{
				UserID:            "nonexistent",
				VerificationToken: "token123",
			},
			setupVerif: &verification.Verification{
				Identifier: "newemail@example.com",
				Token:      "token123",
				Type:       verification.TypeEmailChange,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			expectedError: "failed to find user: user not found",
		},
		{
			name: "successful email change",
			request: &ConfirmChangeEmailRequest{
				UserID:            "user123",
				VerificationToken: "valid_token",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setupVerif: &verification.Verification{
				Identifier: "newemail@example.com",
				Token:      "valid_token",
				Type:       verification.TypeEmailChange,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			expectedNewEmail: "newemail@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userRepo := memory.NewUserRepository()
			verificationRepo := memory.NewVerificationRepository()

			// Setup user with consistent ID
			testUserID := "test-user-id"
			if tt.setupUser != nil {
				tt.setupUser.ID = testUserID
				if err := userRepo.Create(tt.setupUser); err != nil {
					t.Fatalf("failed to setup user: %v", err)
				}
				// Update request with actual user ID
				if tt.request != nil && tt.request.UserID == "user123" {
					tt.request.UserID = testUserID
				}
			}

			// Setup verification
			if tt.setupVerif != nil {
				tt.setupVerif.ID = "test-verif-id"
				if err := verificationRepo.Create(tt.setupVerif); err != nil {
					t.Fatalf("failed to setup verification: %v", err)
				}
			}

			svc := &Service{
				userRepo:         userRepo,
				verificationRepo: verificationRepo,
			}

			resp, err := svc.ConfirmChangeEmail(tt.request)

			if tt.expectedError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %v", tt.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if resp == nil {
				t.Errorf("expected response, got nil")
				return
			}

			if resp.User == nil {
				t.Errorf("expected user in response, got nil")
				return
			}

			if resp.User.Email != tt.expectedNewEmail {
				t.Errorf("expected email %q, got %q", tt.expectedNewEmail, resp.User.Email)
			}

			// Verify token was deleted
			if tt.setupVerif != nil {
				retrieved, err := verificationRepo.FindByToken(tt.setupVerif.Token)
				if err == nil && retrieved != nil {
					t.Errorf("expected verification token to be deleted, but found it")
				}
			}
		})
	}
}
