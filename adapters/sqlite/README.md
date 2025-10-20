# SQLite Infrastructure

This package provides SQLite database adapters and repositories for the go-better-auth library.

## Overview

The SQLite infrastructure layer provides production-ready database implementations for all authentication entities. It uses the `github.com/mattn/go-sqlite3` driver and is fully compatible with the domain interfaces.

## Features

- **Full CRUD Operations**: Complete implementation for all domain models
- **Transaction Support**: Context-aware database operations
- **Foreign Key Constraints**: Enabled by default for referential integrity
- **Automatic Migrations**: SQL migration scripts included
- **Thread-Safe**: Proper connection handling and resource management
- **MFA Support**: Built-in support for Two-Factor Authentication
- **CSRF Protection**: Integrated CSRF token management

## Components

### SQLiteAdapter

The main adapter that manages the SQLite database connection and provides access to all repositories.

```go
import "github.com/m-t-a97/go-better-auth/adapters/sqlite"

// Create adapter
adapter, err := sqlite.NewSQLiteAdapter("./auth.db")
if err != nil {
    log.Fatal(err)
}
defer adapter.Close()

// Get database connection
db := adapter.GetDB()
```

### User Repository

`SQLiteUserRepository` implements user CRUD operations:

```go
userRepo := sqlite.NewSQLiteUserRepository(db)

// Create user
user := &domain.User{
    ID:    "user-123",
    Name:  "John Doe",
    Email: "john@example.com",
}
err := userRepo.Create(ctx, user)

// Find by email
user, err := userRepo.FindByEmail(ctx, "john@example.com")

// Find by ID
user, err := userRepo.FindByID(ctx, "user-123")

// Update
user.Name = "Jane Doe"
err = userRepo.Update(ctx, user)

// Delete
err = userRepo.Delete(ctx, "user-123")
```

### Session Repository

`SQLiteSessionRepository` manages user sessions:

```go
sessionRepo := sqlite.NewSQLiteSessionRepository(db)

// Create session
session := &domain.Session{
    ID:        "session-123",
    UserID:    "user-123",
    Token:     "session-token",
    ExpiresAt: time.Now().Add(24 * time.Hour),
}
err := sessionRepo.Create(ctx, session)

// Find by token
session, err := sessionRepo.FindByToken(ctx, "session-token")

// Find by user ID
sessions, err := sessionRepo.FindByUserID(ctx, "user-123")

// Delete expired sessions
err = sessionRepo.DeleteExpired(ctx)
```

### Account Repository

`SQLiteAccountRepository` handles OAuth and credential accounts:

```go
accountRepo := sqlite.NewSQLiteAccountRepository(db)

// Create account
account := &domain.Account{
    ID:        "account-123",
    UserID:    "user-123",
    ProviderId: "google",
    AccountID: "google-user-id",
}
err := accountRepo.Create(ctx, account)

// Find by user and provider
account, err := accountRepo.FindByUserIDAndProvider(ctx, "user-123", "google")

// Find by provider account ID
account, err := accountRepo.FindByProviderAccountID(ctx, "google", "google-user-id")

// List all accounts for user
accounts, err := accountRepo.ListByUserID(ctx, "user-123")
```

### Verification Repository

`SQLiteVerificationRepository` manages email verification and password reset tokens:

```go
verificationRepo := sqlite.NewSQLiteVerificationRepository(db)

// Create verification token
verification := &domain.Verification{
    ID:        "verify-123",
    Identifier: "email",
    Value:     "test@example.com",
    ExpiresAt: time.Now().Add(24 * time.Hour),
}
err := verificationRepo.Create(ctx, verification)

// Find verification
verification, err := verificationRepo.FindByIdentifierAndValue(ctx, "email", "test@example.com")

// Delete verification
err = verificationRepo.Delete(ctx, "verify-123")

// Clean expired verifications
err = verificationRepo.DeleteExpired(ctx)
```

### MFA Repositories

#### Two-Factor Auth Repository

`TwoFactorAuthAdapter` manages MFA methods:

```go
mfaRepo := sqlite.NewTwoFactorAuthAdapter(db)

// Create MFA configuration
mfa := &domain.TwoFactorAuth{
    UserID:    "user-123",
    Method:    domain.TOTP,
    IsEnabled: false,
    BackupCodes: []string{"code1", "code2"},
}
err := mfaRepo.Create(ctx, mfa)

// Find by user ID
mfa, err := mfaRepo.FindByUserID(ctx, "user-123")

// Find by user and method
mfa, err := mfaRepo.FindByUserIDAndMethod(ctx, "user-123", domain.TOTP)

// Update MFA
mfa.IsEnabled = true
err = mfaRepo.Update(ctx, mfa)
```

#### TOTP Secret Repository

`TOTPSecretAdapter` stores TOTP secrets:

```go
totpRepo := sqlite.NewTOTPSecretAdapter(db)

// Create TOTP secret
secret := &domain.TOTPSecret{
    UserID:    "user-123",
    Secret:    "JBSWY3DPEBLW64TMMQ======",
    QRCode:    "data:image/png;base64,...",
    IsVerified: false,
}
err := totpRepo.Create(ctx, secret)

// Find by user ID
secret, err := totpRepo.FindByUserID(ctx, "user-123")

// Verify TOTP
secret.IsVerified = true
err = totpRepo.Update(ctx, secret)
```

#### MFA Challenge Repository

`MFAChallengeAdapter` manages MFA challenges:

```go
challengeRepo := sqlite.NewMFAChallengeAdapter(db)

// Create challenge
challenge := &domain.MFAChallenge{
    UserID:    "user-123",
    Method:    domain.TOTP,
    Challenge: "123456",
    ExpiresAt: time.Now().Add(5 * time.Minute),
}
err := challengeRepo.Create(ctx, challenge)

// Find challenge
challenge, err := challengeRepo.FindByID(ctx, "challenge-id")

// Clean expired challenges
err = challengeRepo.DeleteExpired(ctx)
```

## Migrations

The SQLite adapter includes two migration constants for schema setup:

### SQLiteMigrationSQL

Defines core authentication tables:
- `users` - User profiles
- `sessions` - User sessions
- `accounts` - OAuth/credential accounts
- `verifications` - Email and password verification tokens

### SQLiteMFAMigrationSQL

Defines MFA-specific tables:
- `two_factor_auth` - MFA method configurations
- `totp_secrets` - TOTP secrets and backup codes
- `mfa_challenges` - Active MFA challenges

### CSRF Migrations

CSRF tables are created via the CSRF repository:

```go
csrfRepo := csrf.NewSQLiteRepository(db)
err := csrfRepo.InitSchema(ctx)
```

## Database Setup

### Basic Setup

```go
import (
    "context"
    "github.com/m-t-a97/go-better-auth/adapters/sqlite"
)

// Create adapter
adapter, err := sqlite.NewSQLiteAdapter("./auth.db")
if err != nil {
    log.Fatal(err)
}
defer adapter.Close()

db := adapter.GetDB()
ctx := context.Background()

// Run migrations
if _, err := db.ExecContext(ctx, sqlite.SQLiteMigrationSQL); err != nil {
    log.Fatal(err)
}

if _, err := db.ExecContext(ctx, sqlite.SQLiteMFAMigrationSQL); err != nil {
    log.Fatal(err)
}
```

### With BetterAuth

The `gobetterauth.New()` function automatically handles SQLite setup:

```go
config := &gobetterauth.Config{
    Database: gobetterauth.DatabaseConfig{
        Provider:         "sqlite",
        ConnectionString: "./auth.db",
    },
    BaseURL: "http://localhost:3000",
    // ... other config
}

auth, err := gobetterauth.New(config)
if err != nil {
    log.Fatal(err)
}
```

## Connection Options

SQLite supports various connection string options:

```go
// Basic file database
adapter, _ := sqlite.NewSQLiteAdapter("./auth.db")

// In-memory (testing only)
adapter, _ := sqlite.NewSQLiteAdapter(":memory:")

// Advanced options
adapter, _ := sqlite.NewSQLiteAdapter("file:./auth.db?cache=shared&mode=rwc")

// URI format with parameters
adapter, _ := sqlite.NewSQLiteAdapter("file:./auth.db?cache=shared&timeout=5000")
```

## Performance Optimization

### Connection Pooling

SQLite uses file-based locking. Optimize connection settings:

```go
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(5 * time.Minute)
```

### WAL Mode

Enable Write-Ahead Logging for better concurrency:

```go
ctx := context.Background()
_, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL")
```

### Cache Settings

```go
_, err := db.ExecContext(ctx, "PRAGMA cache_size=10000")
_, err = db.ExecContext(ctx, "PRAGMA synchronous=NORMAL")
```

## Testing

All repositories are thoroughly tested with comprehensive unit tests:

```bash
# Run all SQLite tests with CGO enabled
CGO_ENABLED=1 go test -v ./adapters/sqlite/...

# Run specific test
CGO_ENABLED=1 go test -v -run TestUserRepository ./adapters/sqlite/...
```

## Best Practices

1. **Always use context**: All operations accept `context.Context` for cancellation and timeouts
2. **Handle errors**: Check error returns for all database operations
3. **Close adapter**: Always defer `adapter.Close()` to clean up resources
4. **Run migrations**: Execute migration SQL before using repositories
5. **Enable foreign keys**: SQLite requires explicit `PRAGMA foreign_keys=ON`
6. **Use transactions**: For multi-step operations, consider using database transactions

## Limitations

SQLite has some limitations compared to PostgreSQL:

- **Limited concurrency**: File-based locking limits concurrent writes
- **Scalability**: Best for databases under 1GB
- **Deployment**: Requires shared file access for multi-server setups
- **Advanced features**: Limited support for complex SQL features

## Migration from/to Other Databases

### From PostgreSQL

Use the migration tools in the `examples/` directory to migrate data.

### To PostgreSQL

The repository interfaces are database-agnostic, making migration straightforward:

1. Create PostgreSQL adapter using `adapters/postgres` package
2. Copy database using ETL tools or custom scripts
3. Update configuration to point to PostgreSQL

## Troubleshooting

### Database Locked

SQLite uses file-based locking. If you see "database is locked":

```go
// Increase timeout
adapter, _ := sqlite.NewSQLiteAdapter("file:./auth.db?timeout=5000")

// Or enable WAL mode
db.ExecContext(ctx, "PRAGMA journal_mode=WAL")
```

### Foreign Key Constraints Fail

Ensure foreign keys are enabled:

```go
db.ExecContext(ctx, "PRAGMA foreign_keys=ON")
```

### Performance Issues

Consider:
- Running `VACUUM` to reclaim space
- Creating appropriate indexes
- Using WAL mode for concurrent access
- Adjusting cache size based on workload

## See Also

- [SQLite Official Documentation](https://www.sqlite.org/docs.html)
- [go-sqlite3 Driver](https://github.com/mattn/go-sqlite3)
- [go-better-auth Documentation](../../docs/SQLITE_INTEGRATION.md)
- [PostgreSQL Infrastructure](../postgres/)
