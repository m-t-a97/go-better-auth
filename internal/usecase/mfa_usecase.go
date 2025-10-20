package usecase

import (
	"context"
	"time"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/pkg/mfa"
)

// MFAUseCase handles two-factor authentication business logic
type MFAUseCase struct {
	mfaRepo        domain.TwoFactorAuthRepository
	totpSecretRepo domain.TOTPSecretRepository
	challengeRepo  domain.MFAChallengeRepository
	totpManager    *mfa.TOTPManager
}

// NewMFAUseCase creates a new MFA use case
func NewMFAUseCase(
	mfaRepo domain.TwoFactorAuthRepository,
	totpSecretRepo domain.TOTPSecretRepository,
	challengeRepo domain.MFAChallengeRepository,
	totpManager *mfa.TOTPManager,
) *MFAUseCase {
	return &MFAUseCase{
		mfaRepo:        mfaRepo,
		totpSecretRepo: totpSecretRepo,
		challengeRepo:  challengeRepo,
		totpManager:    totpManager,
	}
}

// EnableTOTPInput represents the input for enabling TOTP
type EnableTOTPInput struct {
	UserID string
	Email  string
}

// EnableTOTPOutput represents the output of enabling TOTP
type EnableTOTPOutput struct {
	Secret      string   // Base32 encoded secret
	QRCode      string   // QR code URL
	BackupCodes []string // Backup codes
}

// EnableTOTP generates a new TOTP secret for a user
func (uc *MFAUseCase) EnableTOTP(ctx context.Context, input *EnableTOTPInput) (*EnableTOTPOutput, error) {
	// Check if user already has TOTP enabled
	_, err := uc.totpSecretRepo.FindByUserID(ctx, input.UserID)
	if err == nil {
		// User already has TOTP enabled
		return nil, domain.ErrInvalidRequest
	}

	// Generate new TOTP secret
	totpSecret, err := uc.totpManager.GenerateSecret(input.Email)
	if err != nil {
		return nil, err
	}

	// Generate backup codes
	backupCodes, err := uc.totpManager.GenerateBackupCodes(10)
	if err != nil {
		return nil, err
	}

	// Store the TOTP secret (unverified)
	secret := &domain.TOTPSecret{
		UserID:            input.UserID,
		Secret:            totpSecret.Secret,
		QRCode:            totpSecret.QRCode,
		BackupCodes:       backupCodes,
		IsVerified:        false,
		VerificationCount: 0,
	}

	err = uc.totpSecretRepo.Create(ctx, secret)
	if err != nil {
		return nil, err
	}

	return &EnableTOTPOutput{
		Secret:      totpSecret.Secret,
		QRCode:      totpSecret.QRCode,
		BackupCodes: backupCodes,
	}, nil
}

// VerifyTOTPInput represents the input for verifying TOTP
type VerifyTOTPInput struct {
	UserID string
	Code   string
}

// VerifyTOTPSetup verifies and enables TOTP for a user
func (uc *MFAUseCase) VerifyTOTPSetup(ctx context.Context, input *VerifyTOTPInput) error {
	// Get the pending TOTP secret
	totpSecret, err := uc.totpSecretRepo.FindByUserID(ctx, input.UserID)
	if err != nil {
		return domain.ErrMFANotEnabled
	}

	if totpSecret.IsVerified {
		return domain.ErrInvalidRequest
	}

	// Verify the TOTP code
	if !uc.totpManager.VerifyCode(totpSecret.Secret, input.Code) {
		return domain.ErrInvalidMFACode
	}

	// Mark as verified
	now := time.Now().UTC()
	totpSecret.IsVerified = true
	totpSecret.VerificationCount++
	totpSecret.VerifiedAt = &now

	err = uc.totpSecretRepo.Update(ctx, totpSecret)
	if err != nil {
		return err
	}

	// Create or update MFA record
	mfaRecord, err := uc.mfaRepo.FindByUserIDAndMethod(ctx, input.UserID, domain.TOTP)
	if err != nil {
		// Create new MFA record
		mfaRecord = &domain.TwoFactorAuth{
			UserID:      input.UserID,
			Method:      domain.TOTP,
			IsEnabled:   true,
			BackupCodes: totpSecret.BackupCodes,
			VerifiedAt:  &now,
		}
		err = uc.mfaRepo.Create(ctx, mfaRecord)
	} else {
		// Update existing MFA record
		mfaRecord.IsEnabled = true
		mfaRecord.BackupCodes = totpSecret.BackupCodes
		mfaRecord.VerifiedAt = &now
		err = uc.mfaRepo.Update(ctx, mfaRecord)
	}

	return err
}

// VerifyMFACodeInput represents the input for verifying MFA code during login
type VerifyMFACodeInput struct {
	UserID      string
	Code        string
	ChallengeID string
}

// VerifyMFACode verifies an MFA code during login
func (uc *MFAUseCase) VerifyMFACode(ctx context.Context, input *VerifyMFACodeInput) (*domain.TwoFactorAuth, error) {
	// Get the MFA challenge
	challenge, err := uc.challengeRepo.FindByID(ctx, input.ChallengeID)
	if err != nil {
		return nil, domain.ErrInvalidMFACode
	}

	// Verify the challenge belongs to the user
	if challenge.UserID != input.UserID {
		return nil, domain.ErrInvalidMFACode
	}

	// Get MFA record
	mfaRecord, err := uc.mfaRepo.FindByUserIDAndMethod(ctx, input.UserID, domain.TOTP)
	if err != nil {
		return nil, domain.ErrMFANotEnabled
	}

	// Get TOTP secret
	totpSecret, err := uc.totpSecretRepo.FindByUserID(ctx, input.UserID)
	if err != nil {
		return nil, domain.ErrMFANotEnabled
	}

	// Verify code or check if it's a backup code
	isBackupCode := false
	for i, backupCode := range mfaRecord.BackupCodes {
		if backupCode == input.Code {
			isBackupCode = true
			// Remove used backup code
			mfaRecord.BackupCodes = append(mfaRecord.BackupCodes[:i], mfaRecord.BackupCodes[i+1:]...)
			break
		}
	}

	if !isBackupCode {
		// Verify TOTP code
		if !uc.totpManager.VerifyCode(totpSecret.Secret, input.Code) {
			return nil, domain.ErrInvalidMFACode
		}
	} else {
		// Update backup codes if used
		err = uc.mfaRepo.Update(ctx, mfaRecord)
		if err != nil {
			return nil, err
		}
	}

	// Delete the challenge
	err = uc.challengeRepo.Delete(ctx, input.ChallengeID)
	if err != nil {
		return nil, err
	}

	return mfaRecord, nil
}

// CreateMFAChallengeInput represents input for creating an MFA challenge
type CreateMFAChallengeInput struct {
	UserID string
	Method domain.TwoFactorAuthMethod
}

// CreateMFAChallenge creates a new MFA challenge for login
func (uc *MFAUseCase) CreateMFAChallenge(ctx context.Context, input *CreateMFAChallengeInput) (*domain.MFAChallenge, error) {
	// Verify user has MFA enabled
	mfaRecord, err := uc.mfaRepo.FindByUserIDAndMethod(ctx, input.UserID, input.Method)
	if err != nil || !mfaRecord.IsEnabled {
		return nil, domain.ErrMFANotEnabled
	}

	// Create challenge
	challenge := &domain.MFAChallenge{
		UserID:    input.UserID,
		Method:    input.Method,
		Challenge: "", // Can be populated by caller if needed
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}

	err = uc.challengeRepo.Create(ctx, challenge)
	if err != nil {
		return nil, err
	}

	return challenge, nil
}

// DisableTOTPInput represents the input for disabling TOTP
type DisableTOTPInput struct {
	UserID string
}

// DisableTOTP disables TOTP for a user
func (uc *MFAUseCase) DisableTOTP(ctx context.Context, input *DisableTOTPInput) error {
	// Delete MFA record
	err := uc.mfaRepo.DeleteByUserID(ctx, input.UserID)
	if err != nil {
		return err
	}

	// Delete TOTP secret
	err = uc.totpSecretRepo.DeleteByUserID(ctx, input.UserID)
	if err != nil {
		return err
	}

	return nil
}

// GetMFAStatusOutput represents the output of getting MFA status
type GetMFAStatusOutput struct {
	IsEnabled       bool
	Method          domain.TwoFactorAuthMethod
	BackupCodesLeft int
	VerifiedAt      *time.Time
}

// GetMFAStatus retrieves the MFA status for a user
func (uc *MFAUseCase) GetMFAStatus(ctx context.Context, userID string) (*GetMFAStatusOutput, error) {
	mfaRecord, err := uc.mfaRepo.FindByUserID(ctx, userID)
	if err != nil {
		return &GetMFAStatusOutput{
			IsEnabled: false,
		}, nil
	}

	return &GetMFAStatusOutput{
		IsEnabled:       mfaRecord.IsEnabled,
		Method:          mfaRecord.Method,
		BackupCodesLeft: len(mfaRecord.BackupCodes),
		VerifiedAt:      mfaRecord.VerifiedAt,
	}, nil
}
