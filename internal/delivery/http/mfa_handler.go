package http

import (
	"encoding/json"
	"net/http"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/internal/usecase"
)

// MFAHandler represents the MFA HTTP handler
type MFAHandler struct {
	mfaUseCase *usecase.MFAUseCase
}

// NewMFAHandler creates a new MFA HTTP handler
func NewMFAHandler(mfaUseCase *usecase.MFAUseCase) *MFAHandler {
	return &MFAHandler{
		mfaUseCase: mfaUseCase,
	}
}

// EnableTOTPRequest represents the request to enable TOTP
type EnableTOTPRequest struct {
	Email string `json:"email"`
}

// EnableTOTPResponse represents the response when enabling TOTP
type EnableTOTPResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qrCode"`
	BackupCodes []string `json:"backupCodes"`
}

// EnableTOTP generates a new TOTP secret
func (h *MFAHandler) EnableTOTP(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	var req EnableTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	output, err := h.mfaUseCase.EnableTOTP(r.Context(), &usecase.EnableTOTPInput{
		UserID: user.ID,
		Email:  req.Email,
	})
	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, EnableTOTPResponse{
		Secret:      output.Secret,
		QRCode:      output.QRCode,
		BackupCodes: output.BackupCodes,
	})
}

// VerifyTOTPRequest represents the request to verify TOTP setup
type VerifyTOTPRequest struct {
	Code string `json:"code"`
}

// VerifyTOTPSetup verifies the TOTP code and completes the setup
func (h *MFAHandler) VerifyTOTPSetup(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	var req VerifyTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	err := h.mfaUseCase.VerifyTOTPSetup(r.Context(), &usecase.VerifyTOTPInput{
		UserID: user.ID,
		Code:   req.Code,
	})
	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Two-factor authentication enabled successfully",
	})
}

// VerifyMFARequest represents the request to verify MFA during login
type VerifyMFARequest struct {
	Code        string `json:"code"`
	ChallengeID string `json:"challengeId"`
}

// VerifyMFACode verifies an MFA code during login
func (h *MFAHandler) VerifyMFACode(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	var req VerifyMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	mfaRecord, err := h.mfaUseCase.VerifyMFACode(r.Context(), &usecase.VerifyMFACodeInput{
		UserID:      user.ID,
		Code:        req.Code,
		ChallengeID: req.ChallengeID,
	})
	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "MFA verification successful",
		"mfa": map[string]any{
			"method":      mfaRecord.Method,
			"backupCodes": len(mfaRecord.BackupCodes),
		},
	})
}

// DisableTOTPRequest represents the request to disable TOTP
type DisableTOTPRequest struct {
	Password string `json:"password"`
}

// DisableTOTP disables TOTP for the user
func (h *MFAHandler) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	err := h.mfaUseCase.DisableTOTP(r.Context(), &usecase.DisableTOTPInput{
		UserID: user.ID,
	})
	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Two-factor authentication disabled",
	})
}

// MFAStatusResponse represents the response with MFA status
type MFAStatusResponse struct {
	IsEnabled       bool    `json:"isEnabled"`
	Method          string  `json:"method,omitempty"`
	BackupCodesLeft int     `json:"backupCodesLeft"`
	VerifiedAt      *string `json:"verifiedAt,omitempty"`
}

// GetMFAStatus retrieves the MFA status for the user
func (h *MFAHandler) GetMFAStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	status, err := h.mfaUseCase.GetMFAStatus(r.Context(), user.ID)
	if err != nil {
		respondError(w, err)
		return
	}

	var verifiedAt *string
	if status.VerifiedAt != nil {
		t := status.VerifiedAt.String()
		verifiedAt = &t
	}

	respondJSON(w, http.StatusOK, MFAStatusResponse{
		IsEnabled:       status.IsEnabled,
		Method:          string(status.Method),
		BackupCodesLeft: status.BackupCodesLeft,
		VerifiedAt:      verifiedAt,
	})
}
