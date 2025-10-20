# MFA Package

The `mfa` package provides Time-Based One-Time Password (TOTP) authentication support for Go-Better-Auth.

## Overview

This package includes:
- TOTP generation and verification
- QR code generation for authenticator apps
- Backup code generation
- In-memory and PostgreSQL storage adapters
- Comprehensive test coverage

## Components

### TOTPManager

Handles TOTP operations:

```go
manager := mfa.NewTOTPManager("YourAppName")

// Generate a new secret
secret, err := manager.GenerateSecret("user@example.com")
// secret.Secret: Base32 encoded TOTP secret
// secret.QRCode: QR code URL for authenticator app

// Verify a code
isValid := manager.VerifyCode(secret.Secret, "123456")

// Generate backup codes
codes, err := manager.GenerateBackupCodes(10)
```

### Repositories

#### In-Memory (Testing)

```go
mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
```

#### PostgreSQL (Production)

```go
mfaRepo := postgres.NewTwoFactorAuthAdapter(db)
totpSecretRepo := postgres.NewTOTPSecretAdapter(db)
challengeRepo := postgres.NewMFAChallengeAdapter(db)
```

## Usage Example

```go
package main

import (
	"context"
	"fmt"

	"github.com/m-t-a97/go-better-auth/internal/usecase"
	"github.com/m-t-a97/go-better-auth/pkg/mfa"
)

func main() {
	ctx := context.Background()

	// Setup repositories and manager
	mfaRepo := mfa.NewInMemoryTwoFactorAuthRepository()
	totpSecretRepo := mfa.NewInMemoryTOTPSecretRepository()
	challengeRepo := mfa.NewInMemoryMFAChallengeRepository()
	manager := mfa.NewTOTPManager("MyApp")

	// Create MFA use case
	mfaUseCase := usecase.NewMFAUseCase(mfaRepo, totpSecretRepo, challengeRepo, manager)

	// Enable TOTP for a user
	output, err := mfaUseCase.EnableTOTP(ctx, &usecase.EnableTOTPInput{
		UserID: "user123",
		Email:  "user@example.com",
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Secret: %s\n", output.Secret)
	fmt.Printf("QR Code: %s\n", output.QRCode)
	fmt.Printf("Backup Codes: %v\n", output.BackupCodes)

	// Get current TOTP code
	code, err := manager.GetCurrentCode(output.Secret)
	if err != nil {
		panic(err)
	}

	// Verify TOTP setup
	err = mfaUseCase.VerifyTOTPSetup(ctx, &usecase.VerifyTOTPInput{
		UserID: "user123",
		Code:   code,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("TOTP setup verified successfully!")
}
```

## API Reference

### TOTPManager

#### GenerateSecret(email string) (*TOTPSecret, error)
Generates a new TOTP secret with QR code URL.

#### VerifyCode(secret, code string) bool
Verifies a TOTP code against the secret.

#### VerifyCodeWithTime(secret, code string, t time.Time) bool
Verifies a TOTP code at a specific point in time (useful for testing).

#### GenerateBackupCodes(count int) ([]string, error)
Generates n backup codes for account recovery.

#### GetCurrentCode(secret string) (string, error)
Gets the current TOTP code for a secret (useful for testing).

#### GenerateProvisioningURI(email, secret string) string
Generates a provisioning URI for manual entry into authenticator apps.

## Security Considerations

- TOTP secrets are Base32 encoded and should be stored securely
- Backup codes are single-use and should be hashed before storage
- Verification codes have a 30-second validity window by default
- Adjacent time windows (±1 step) are accepted to account for clock skew
- Use HTTPS only for all MFA endpoints
- Implement rate limiting on code verification endpoints

## Testing

The package includes comprehensive unit tests:

```bash
go test ./pkg/mfa -v
```

Tests cover:
- Secret generation and encoding
- TOTP code verification
- Backup code generation
- Time-based code validation
- Edge cases and error handling

## Dependencies

- `github.com/pquerna/otp` - TOTP implementation
- `golang.org/x/crypto` - Cryptographic functions

## Integration

This package is used by:
- `internal/usecase/mfa_usecase.go` - MFA business logic
- `internal/delivery/http/mfa_handler.go` - HTTP handlers
- `internal/infrastructure/postgres/mfa_adapter.go` - Database persistence
