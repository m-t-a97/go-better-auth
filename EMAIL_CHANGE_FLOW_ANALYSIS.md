# Email Change Flow Analysis

## Overview

The email change functionality consists of two main steps:

1. **Initiation**: User requests an email change via `POST /auth/change-email`
2. **Verification**: User confirms the email change via `GET /auth/verify-email?token=...`

## Complete Flow

### Step 1: Request Email Change

**Handler**: `handler/change_email.go` → `ChangeEmailHandler`
**Use Case**: `usecase/auth/change_email.go` → `Service.ChangeEmail`

**What Happens**:

1. User sends POST request with new email address
2. Handler extracts user ID from authentication context
3. Use case validates:
   - User exists
   - New email format is valid
   - New email is not already in use
   - New email is different from current email
4. System generates a verification token
5. Creates a `verification` record with:
   - `user_id`: The authenticated user's ID
   - `identifier`: The new email address
   - `token`: The verification token
   - `type`: `TypeEmailChange`
   - `expires_at`: 24 hours from now
6. Sends verification email to the NEW email address (async)
7. Returns success response

**Important**: The user's email is NOT changed yet - only a verification token is created.

### Step 2: Verify Email Change

**Handler**: `handler/email_verification.go` → `VerifyEmailHandler`
**Use Case**: `usecase/auth/verification_handler.go` → `Service.VerifyEmail`

**What Happens**:

1. User receives verification link in their new email inbox
2. User clicks link: `GET /auth/verify-email?token=<verification_token>`
3. Handler extracts token from query parameter
4. Use case:
   - Finds the verification record by token
   - Validates token hasn't expired
   - Routes to `handleEmailChange` based on verification type
5. In `handleEmailChange`:
   - Retrieves the user by the stored user ID
   - Updates user's email to the new email (stored in `identifier`)
   - Deletes the verification token
   - Returns success

**Result**: User's email is now updated in the database.

## Code Flow Diagram

```
POST /auth/change-email
  ↓
ChangeEmailHandler
  ↓
Service.ChangeEmail(ctx, request)
  ├─ Validate user exists
  ├─ Validate new email
  ├─ Generate verification token
  ├─ Create verification record (stored_email = new_email)
  ├─ Send async email to new address with verification link
  └─ Return success

[User receives email and clicks link]

GET /auth/verify-email?token=xyz
  ↓
VerifyEmailHandler
  ↓
Service.VerifyEmail(ctx, request)
  ├─ Find verification by token
  ├─ Check not expired
  ├─ Route to handleEmailChange (for TypeEmailChange)
  │   ├─ Find user by user_id
  │   ├─ Update user.email = identifier (new email)
  │   └─ Delete verification token
  └─ Return success
```

## File References

| File                                   | Responsibility                                 |
| -------------------------------------- | ---------------------------------------------- |
| `handler/change_email.go`              | HTTP endpoint for requesting email change      |
| `handler/email_verification.go`        | HTTP endpoint for verifying email              |
| `usecase/auth/change_email.go`         | Business logic for email change request        |
| `usecase/auth/verification_handler.go` | Unified verification handler (handles 3 types) |
| `domain/verification/entity.go`        | Verification domain entity                     |
| `adapter/sqlite/user.go`               | SQLite user repository                         |
| `adapter/postgres/user.go`             | PostgreSQL user repository                     |
| `repository/memory/user.go`            | In-memory user repository (for testing)        |

## Database Tables

### `users` table

```sql
id TEXT PRIMARY KEY
name TEXT
email TEXT UNIQUE
email_verified BOOLEAN
image TEXT
created_at TIMESTAMP
updated_at TIMESTAMP
```

### `verifications` table

```sql
id TEXT PRIMARY KEY
user_id TEXT
identifier TEXT (stores new email for email change)
token TEXT
type TEXT (TypeEmailChange, TypeEmailVerification, TypePasswordReset)
expires_at TIMESTAMP
created_at TIMESTAMP
updated_at TIMESTAMP
```

## Common Issues & Troubleshooting

### Issue 1: "Email change didn't happen after verification"

**Possible Causes**:

1. **Verification email not received**

   - Check email configuration in `config.User.ChangeEmail.SendChangeEmailVerification`
   - Verify the email is being sent to the new email address
   - Check email service logs

2. **Wrong verification endpoint used**

   - Must use `GET /auth/verify-email?token=...` (not POST)
   - Token must match exactly (case-sensitive)
   - Token must not be expired (24-hour window)

3. **Multiple verification tokens created**

   - If user requests email change multiple times, multiple tokens are created
   - Only the latest token will work
   - Previous tokens become invalid (not deleted, just won't match)

4. **User not found after email change**

   - Email lookup might still use old email
   - Always use user ID for lookups after email change
   - The `users` table email field SHOULD be updated

5. **Transaction issues (database-specific)**
   - Email update might be rolled back
   - Check database transaction logs

### Issue 2: "Can't find user by new email after change"

**Root Cause**: Verification token was deleted but user email wasn't updated.

**Check**:

```sql
SELECT id, email, updated_at FROM users WHERE id = '<user_id>';
```

The email should be the NEW email, and `updated_at` should be recent.

### Issue 3: "Email verification sends to old email instead of new email"

**Check Configuration**: `config.User.ChangeEmail.SendChangeEmailVerification` callback must use the `newEmail` parameter, NOT the user's current email.

```go
SendChangeEmailVerification: func(ctx context.Context, user *domain.User, newEmail string, url string, token string) error {
    // WRONG: Send to user.Email (old email)
    // CORRECT: Send to newEmail parameter
    return sendEmail(newEmail, "Verify your new email", url)
}
```

## Testing

The functionality is tested in `usecase/auth/verification_handler_test.go`:

```go
{
    name: "email change verification",
    request: &VerifyEmailRequest{
        VerificationToken: "valid_email_change_token",
    },
    setupUser: &user.User{
        ID:            "user123",
        Email:         "oldemail@example.com",
    },
    setupVerif: &verification.Verification{
        UserID:     "user123",
        Identifier: "newemail@example.com",  // New email stored here
        Token:      "valid_email_change_token",
        Type:       verification.TypeEmailChange,
    },
    expectedEmailAfter: "newemail@example.com",  // Verify email was updated
}
```

## How to Debug

1. **Enable query logging**:

   ```go
   config := &domain.Config{
       Database: domain.DatabaseConfig{
           Provider: "sqlite",
           LogQueries: true,  // Enable this
       },
   }
   ```

2. **Check verification record exists**:

   ```sql
   SELECT * FROM verifications
   WHERE type = 'email_change'
   AND user_id = '<user_id>'
   ORDER BY created_at DESC LIMIT 1;
   ```

3. **Verify email was updated**:

   ```sql
   SELECT id, email, updated_at FROM users
   WHERE id = '<user_id>';
   ```

4. **Check token hasn't expired**:
   ```
   Current time > expires_at means token is expired
   ```

## Summary

The email change implementation follows a two-step verification process:

1. **Step 1 (ChangeEmail)**: Create verification token, store new email in `identifier` field, send email
2. **Step 2 (VerifyEmail)**: Validate token, update user email from `identifier`, delete token

Both steps must complete successfully for the email to change. If you're experiencing issues:

- Check that verification email is being sent
- Verify the link is being clicked
- Confirm the token hasn't expired
- Use query logging to see actual SQL updates
