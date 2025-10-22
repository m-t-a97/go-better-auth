package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/middleware"
	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// GetProfileRequest is the HTTP request for getting a user profile
type GetProfileRequest struct {
	UserID string `json:"user_id"`
}

// GetProfileResponse is the HTTP response for getting a user profile
type GetProfileResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Image         string `json:"image,omitempty"`
}

// GetProfileHandler handles GET /auth/me
// Requires AuthMiddleware to be applied to extract user ID from context
func GetProfileHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Get user ID from context (set by AuthMiddleware)
		userID := middleware.MustGetUserID(r.Context())

		// Call use case
		resp, err := svc.GetProfile(&auth.GetProfileRequest{
			UserID: userID,
		})
		if err != nil {
			// Map error to HTTP status
			switch err.Error() {
			case "user ID is required":
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case "user not found":
				ErrorResponse(w, http.StatusNotFound, "user not found")
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := GetProfileResponse{
			ID:            resp.User.ID,
			Email:         resp.User.Email,
			Name:          resp.User.Name,
			EmailVerified: resp.User.EmailVerified,
		}
		if resp.User.Image != nil {
			httpResp.Image = *resp.User.Image
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}

// UpdateProfileRequest is the HTTP request for updating a user profile
type UpdateProfileRequest struct {
	Name  *string `json:"name,omitempty"`
	Image *string `json:"image,omitempty"`
}

// UpdateProfileResponse is the HTTP response for updating a user profile
type UpdateProfileResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Image         string `json:"image,omitempty"`
}

// UpdateProfileHandler handles PATCH /auth/me
// Requires AuthMiddleware to be applied to extract user ID from context
func UpdateProfileHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Get user ID from context (set by AuthMiddleware)
		userID := middleware.MustGetUserID(r.Context())

		// Parse request body
		var req UpdateProfileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		updateResp, err := svc.UpdateUser(&auth.UpdateUserRequest{
			UserID: userID,
			Name:   req.Name,
			Image:  req.Image,
		})
		if err != nil {
			// Map error to HTTP status
			switch {
			case strings.Contains(err.Error(), "user not found"):
				ErrorResponse(w, http.StatusNotFound, "user not found")
			case strings.Contains(err.Error(), "invalid request"):
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := UpdateProfileResponse{
			ID:            updateResp.User.ID,
			Email:         updateResp.User.Email,
			Name:          updateResp.User.Name,
			EmailVerified: updateResp.User.EmailVerified,
		}
		if updateResp.User.Image != nil {
			httpResp.Image = *updateResp.User.Image
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}

// DeleteProfileRequest is the HTTP request for deleting a user profile
type DeleteProfileRequest struct {
	ConfirmPassword string `json:"confirm_password"`
}

// DeleteProfileResponse is the HTTP response for deleting a user profile
type DeleteProfileResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// DeleteProfileHandler handles DELETE /auth/me
// Requires AuthMiddleware to be applied to extract user ID from context
func DeleteProfileHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Get user ID from context (set by AuthMiddleware)
		userID := middleware.MustGetUserID(r.Context())

		// For security, require confirmation password in request body
		var req DeleteProfileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.ConfirmPassword == "" {
			ErrorResponse(w, http.StatusBadRequest, "confirm_password is required")
			return
		}

		// Call use case
		deleteResp, err := svc.DeleteUser(&auth.DeleteUserRequest{
			UserID: userID,
		})
		if err != nil {
			// Map error to HTTP status
			switch {
			case strings.Contains(err.Error(), "user not found"):
				ErrorResponse(w, http.StatusNotFound, "user not found")
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := DeleteProfileResponse{
			Success: deleteResp.Success,
			Message: "account successfully deleted",
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}

// RequestChangeEmailRequest is the HTTP request for requesting an email change
type RequestChangeEmailRequest struct {
	NewEmail string `json:"new_email"`
}

// RequestChangeEmailResponse is the HTTP response for requesting an email change
type RequestChangeEmailResponse struct {
	Message string `json:"message"`
}

// RequestChangeEmailHandler handles POST /auth/change-email
// Requires AuthMiddleware to be applied to extract user ID from context
// Initiates an email change by sending a verification token to the new email
func RequestChangeEmailHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Get user ID from context (set by AuthMiddleware)
		userID := middleware.MustGetUserID(r.Context())

		// Parse request body
		var req RequestChangeEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		resp, err := svc.RequestChangeEmail(r.Context(), &auth.RequestChangeEmailRequest{
			UserID:   userID,
			NewEmail: req.NewEmail,
		})
		if err != nil {
			// Map error to HTTP status
			switch {
			case strings.Contains(err.Error(), "user ID is required"):
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case strings.Contains(err.Error(), "new email is required"):
				ErrorResponse(w, http.StatusBadRequest, "new_email is required")
			case strings.Contains(err.Error(), "invalid email"):
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case strings.Contains(err.Error(), "user not found"):
				ErrorResponse(w, http.StatusNotFound, "user not found")
			case strings.Contains(err.Error(), "new email is the same as current email"):
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case strings.Contains(err.Error(), "email is already in use"):
				ErrorResponse(w, http.StatusConflict, err.Error())
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := RequestChangeEmailResponse{
			Message: "verification email sent to " + resp.Verification.Identifier,
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}

// ConfirmChangeEmailRequest is the HTTP request for confirming an email change
type ConfirmChangeEmailRequest struct {
	VerificationToken string `json:"verification_token"`
}

// ConfirmChangeEmailResponse is the HTTP response for confirming an email change
type ConfirmChangeEmailResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Image         string `json:"image,omitempty"`
}

// ConfirmChangeEmailHandler handles POST /auth/change-email/confirm
// Requires AuthMiddleware to be applied to extract user ID from context
// Confirms an email change by verifying the token
func ConfirmChangeEmailHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			ErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Get user ID from context (set by AuthMiddleware)
		userID := middleware.MustGetUserID(r.Context())

		// Parse request body
		var req ConfirmChangeEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ErrorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Call use case
		resp, err := svc.ConfirmChangeEmail(&auth.ConfirmChangeEmailRequest{
			UserID:            userID,
			VerificationToken: req.VerificationToken,
		})
		if err != nil {
			// Map error to HTTP status
			switch {
			case strings.Contains(err.Error(), "user ID is required"):
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case strings.Contains(err.Error(), "verification token is required"):
				ErrorResponse(w, http.StatusBadRequest, "verification_token is required")
			case strings.Contains(err.Error(), "invalid verification token"):
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case strings.Contains(err.Error(), "verification token has expired"):
				ErrorResponse(w, http.StatusBadRequest, err.Error())
			case strings.Contains(err.Error(), "user not found"):
				ErrorResponse(w, http.StatusNotFound, "user not found")
			case strings.Contains(err.Error(), "email is already in use"):
				ErrorResponse(w, http.StatusConflict, err.Error())
			default:
				ErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
			return
		}

		// Build response
		httpResp := ConfirmChangeEmailResponse{
			ID:            resp.User.ID,
			Email:         resp.User.Email,
			Name:          resp.User.Name,
			EmailVerified: resp.User.EmailVerified,
		}
		if resp.User.Image != nil {
			httpResp.Image = *resp.User.Image
		}

		SuccessResponse(w, http.StatusOK, httpResp)
	}
}
