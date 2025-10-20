package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/pkg/mfa"
)

func TestMFAUseCase_EnableTOTP(t *testing.T) {
	ctx := context.Background()

	// Setup repositories
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	totpManager := mfa.NewTOTPManager("TestApp")

	useCase := NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, totpManager)

	// Test EnableTOTP
	output, err := useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, output.Secret)
	assert.NotEmpty(t, output.QRCode)
	assert.Len(t, output.BackupCodes, 10)
}

func TestMFAUseCase_EnableTOTP_Duplicate(t *testing.T) {
	ctx := context.Background()

	// Setup repositories
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	totpManager := mfa.NewTOTPManager("TestApp")

	useCase := NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, totpManager)

	// First enable
	_, err := useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})
	require.NoError(t, err)

	// Second enable should fail
	_, err = useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})
	assert.NotNil(t, err)
}

func TestMFAUseCase_VerifyTOTPSetup(t *testing.T) {
	ctx := context.Background()

	// Setup repositories
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	totpManager := mfa.NewTOTPManager("TestApp")

	useCase := NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, totpManager)

	// Enable TOTP
	output, err := useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})
	require.NoError(t, err)

	// Get valid code
	validCode, err := totpManager.GetCurrentCode(output.Secret)
	require.NoError(t, err)

	// Verify setup
	err = useCase.VerifyTOTPSetup(ctx, &VerifyTOTPInput{
		UserID: "user1",
		Code:   validCode,
	})
	assert.NoError(t, err)

	// Check that TOTP is now verified
	secret, err := totpSecretRepo.FindByUserID(ctx, "user1")
	require.NoError(t, err)
	assert.True(t, secret.IsVerified)

	// Check that MFA record was created
	mfaRecord, err := mfaRepo.FindByUserIDAndMethod(ctx, "user1", domain.TOTP)
	require.NoError(t, err)
	assert.True(t, mfaRecord.IsEnabled)
}

func TestMFAUseCase_VerifyTOTPSetup_InvalidCode(t *testing.T) {
	ctx := context.Background()

	// Setup repositories
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	totpManager := mfa.NewTOTPManager("TestApp")

	useCase := NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, totpManager)

	// Enable TOTP
	_, err := useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})
	require.NoError(t, err)

	// Try to verify with invalid code
	err = useCase.VerifyTOTPSetup(ctx, &VerifyTOTPInput{
		UserID: "user1",
		Code:   "000000",
	})
	assert.NotNil(t, err)
}

func TestMFAUseCase_CreateMFAChallenge(t *testing.T) {
	ctx := context.Background()

	// Setup repositories
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	totpManager := mfa.NewTOTPManager("TestApp")

	useCase := NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, totpManager)

	// Setup MFA for user
	output, err := useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})
	require.NoError(t, err)

	validCode, err := totpManager.GetCurrentCode(output.Secret)
	require.NoError(t, err)

	err = useCase.VerifyTOTPSetup(ctx, &VerifyTOTPInput{
		UserID: "user1",
		Code:   validCode,
	})
	require.NoError(t, err)

	// Create MFA challenge
	challenge, err := useCase.CreateMFAChallenge(ctx, &CreateMFAChallengeInput{
		UserID: "user1",
		Method: domain.TOTP,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, challenge.ID)
	assert.Equal(t, "user1", challenge.UserID)
	assert.Equal(t, domain.TOTP, challenge.Method)
	assert.True(t, challenge.ExpiresAt.After(time.Now()))
}

func TestMFAUseCase_VerifyMFACode(t *testing.T) {
	ctx := context.Background()

	// Setup repositories
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	totpManager := mfa.NewTOTPManager("TestApp")

	useCase := NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, totpManager)

	// Setup MFA for user
	output, err := useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})
	require.NoError(t, err)

	validCode, err := totpManager.GetCurrentCode(output.Secret)
	require.NoError(t, err)

	err = useCase.VerifyTOTPSetup(ctx, &VerifyTOTPInput{
		UserID: "user1",
		Code:   validCode,
	})
	require.NoError(t, err)

	// Create MFA challenge
	challenge, err := useCase.CreateMFAChallenge(ctx, &CreateMFAChallengeInput{
		UserID: "user1",
		Method: domain.TOTP,
	})
	require.NoError(t, err)

	// Get new valid code
	validCode2, err := totpManager.GetCurrentCode(output.Secret)
	require.NoError(t, err)

	// Verify MFA code
	mfaRecord, err := useCase.VerifyMFACode(ctx, &VerifyMFACodeInput{
		UserID:      "user1",
		Code:        validCode2,
		ChallengeID: challenge.ID,
	})

	require.NoError(t, err)
	assert.True(t, mfaRecord.IsEnabled)
	assert.Len(t, mfaRecord.BackupCodes, 10)
}

func TestMFAUseCase_DisableTOTP(t *testing.T) {
	ctx := context.Background()

	// Setup repositories
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	totpManager := mfa.NewTOTPManager("TestApp")

	useCase := NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, totpManager)

	// Setup MFA for user
	output, err := useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})
	require.NoError(t, err)

	validCode, err := totpManager.GetCurrentCode(output.Secret)
	require.NoError(t, err)

	err = useCase.VerifyTOTPSetup(ctx, &VerifyTOTPInput{
		UserID: "user1",
		Code:   validCode,
	})
	require.NoError(t, err)

	// Disable TOTP
	err = useCase.DisableTOTP(ctx, &DisableTOTPInput{
		UserID: "user1",
	})
	require.NoError(t, err)

	// Check that MFA is disabled
	status, err := useCase.GetMFAStatus(ctx, "user1")
	require.NoError(t, err)
	assert.False(t, status.IsEnabled)
}

func TestMFAUseCase_GetMFAStatus(t *testing.T) {
	ctx := context.Background()

	// Setup repositories
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	totpManager := mfa.NewTOTPManager("TestApp")

	useCase := NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, totpManager)

	// Check status before enabling
	status, err := useCase.GetMFAStatus(ctx, "user1")
	require.NoError(t, err)
	assert.False(t, status.IsEnabled)

	// Enable TOTP
	output, err := useCase.EnableTOTP(ctx, &EnableTOTPInput{
		UserID: "user1",
		Email:  "user@example.com",
	})
	require.NoError(t, err)

	validCode, err := totpManager.GetCurrentCode(output.Secret)
	require.NoError(t, err)

	err = useCase.VerifyTOTPSetup(ctx, &VerifyTOTPInput{
		UserID: "user1",
		Code:   validCode,
	})
	require.NoError(t, err)

	// Check status after enabling
	status, err = useCase.GetMFAStatus(ctx, "user1")
	require.NoError(t, err)
	assert.True(t, status.IsEnabled)
	assert.Equal(t, domain.TOTP, status.Method)
	assert.Equal(t, 10, status.BackupCodesLeft)
}
