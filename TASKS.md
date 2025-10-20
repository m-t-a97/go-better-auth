# Tasks for go-better-auth Codebase Review

## Overall Observations
- Fix Makefile: `MAIN_PATH` is undefined in the build target, which could cause failures. Suggest defining it (e.g., `MAIN_PATH=./cmd/main.go`).
- Check Go version compatibility: `go.mod` specifies Go 1.25.0, which is ahead of current releases (as of 2025)—ensure compatibility.
- Prioritize adding comprehensive unit tests across all features.
- Verify security implementations (e.g., hashing, token storage) in detail.

## 1. Email & Password Authentication ✅ COMPLETED
- ✅ Add unit tests for email/password authentication flows, including edge cases like weak passwords and duplicate emails.
- ✅ Ensure password policies (e.g., minimum length) are enforced in the usecase layer.

### Tests Implemented:
- TestSignUpEmail (successful signup, duplicate email)
- TestSignInEmail (successful signin, invalid password, non-existent user)
- TestPasswordHashing (hash generation and verification)
- TestSessionManagement (session creation, retrieval, signout)
- TestRefreshSession (session refresh with expiration extension)
- TestRefreshExpiredSession (handling expired session refresh)
- TestCleanExpiredSessions (automatic cleanup of expired sessions)
- TestPasswordPolicyValidation (8+ chars, uppercase, lowercase, digit, special char)
- TestSignUpEmailDuplicateEmail (duplicate email prevention)
- TestChangePasswordWithValidation (password change with policy validation)

## 2. Social OAuth Providers (Google, GitHub, Discord, Generic OAuth2) ✅ COMPLETED
- ✅ Implement and test error handling for OAuth failures (e.g., invalid codes, expired tokens).
- ✅ Add rate limiting to OAuth endpoints.

### Tests Implemented:
- TestOAuthHandleCallback (successful callback with user creation)
- TestOAuthRefreshToken (token refresh flow)
- TestOAuthRefreshTokenExpired (handling expired refresh tokens)
- TestOAuthRefreshTokenNoRefreshToken (handling missing refresh tokens)
- TestOAuthHandleCallbackInvalidCode (invalid authorization code error handling)
- TestOAuthHandleCallbackExpiredToken (expired token error handling)
- TestOAuthHandleCallbackExchangeCodeError (provider error handling)
- TestOAuthHandleCallbackUserInfoError (user info fetch error handling)
- TestOAuthProviderNotFound (non-existent provider error handling)
- TestOAuthGetAuthURLProviderNotFound (auth URL generation for missing provider)
- TestOAuthHandleCallbackExistingUser (account token update for existing users)
- TestOAuthHandleCallbackMultipleProviders (multiple provider registration)
- TestOAuthRateLimitHeaders (rate limit headers in responses)
- TestOAuthRateLimitExceeded (429 response when rate limit exceeded)
- TestOAuthRateLimitByIP (IP-based rate limiting)
- TestOAuthRateLimitMultipleRequests (sequential request counting)
- TestOAuthRateLimitReset (reset time calculation validation)

### Changes:
- **usecase/oauth_usecase_test.go**: Added comprehensive error handling tests with mock providers
- **http/handler.go**: Integrated rate limiting middleware for OAuth endpoints (authorize, callback, refresh)
- **http/ratelimit_test.go**: Added rate limiting middleware tests with mock rate limiter

## 3. Session Management
- Add automated cleanup for expired sessions.
- Ensure session invalidation on password changes, as per security best practices.

## 4. Email Verification
- Add tests for email verification, including token expiry and invalid token handling.
- Add logging for verification attempts to detect abuse.

## 5. Password Reset
- Verify and test session revocation on password changes.
- Add rate limiting to password reset endpoints.

## 6. Multi-Factor Authentication (MFA) - TOTP-based
- Complete and run MFA tests.
- Verify backup code hashing and clock skew handling.

## 7. JWT Support
- Add tests for JWT operations.
- Implement token blacklisting for logout.

## 8. CSRF Protection
- Add unit tests for CSRF token generation and validation.
- Ensure cleanup strategy (e.g., periodic ticker) is thread-safe.
- Integrate with session management for seamless protection.

## 9. Rate Limiting
- Implement and test rate limiting with examples.
- Add fallback to in-memory if Redis is unavailable.

## 10. Plugin System
- Add plugin examples and tests.

## 11. Database Adapters (PostgreSQL, SQLite)
- Test database adapters for transactions.
- Add connection pooling configs.
