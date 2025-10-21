# Tasks

## 1. Core Configuration Management

### 1.1 Base Configuration Structure
- [x] Implement configuration loading from environment variables (GO_BETTER_AUTH_URL, GO_BETTER_AUTH_SECRET, AUTH_SECRET)
- [x] Add configuration validation at startup with proper error messages
- [x] Implement default values for all config fields
- [x] Create configuration merging logic for defaults and user-provided config

### 1.2 Trusted Origins & CORS
- [x] Implement static origins validation
- [x] Add dynamic origins function support
- [x] Create CORS middleware for HTTP handlers
- [x] Add wildcard pattern matching for origins

### 1.3 Secret Management
- [x] Implement secret validation (required in production)
- [x] Add secure secret generation utilities
- [x] Create encryption/signing utilities using the secret

## 2. Database Layer

### 2.1 Database Adapters
- [x] Implement SQLite adapter with connection pooling
- [x] Implement PostgreSQL adapter with connection pooling

### 2.2 Repository Pattern
- [x] Define repository interfaces in domain layer
- [x] Implement generic CRUD operations
- [x] Add transaction support for multi-table operations
- [x] Create database-specific implementations for SQLite/PostgreSQL (in-memory only, database adapters pending)

### 2.3 Schema Management
- [x] Design and implement user table schema
- [x] Design and implement session table schema
- [x] Design and implement account table schema
- [x] Design and implement verification table schema
<!-- - [ ] Add support for custom fields and additional fields -->

## 3. User Management

### 3.1 Domain Layer
- [x] Define User entity with core fields (id, email, name, etc.)
- [x] Create UserRepository interface
- [x] Add user validation rules (email format, password strength)

### 3.2 User Operations
- [x] Implement user creation usecase
- [x] Implement user retrieval usecases (by ID, email)
- [x] Implement user update usecase
- [x] Implement user deletion usecase with hooks
- [x] Create HTTP handlers for update and delete operations

### 3.3 User Features
- [x] Implement change email functionality with verification
- [x] Add email verification system integration
- [x] Create user deletion with before/after hooks

## 4. Session Management

### 4.1 Domain Layer
- [x] Define Session entity
- [x] Create SessionRepository interface
- [x] Add session validation business rules

### 4.2 Session Operations
- [x] Implement session creation usecase
- [x] Implement session validation usecase
- [x] Implement session refresh usecase
- [x] Implement session deletion usecase

### 4.3 Session Storage
- [x] Implement database session storage
- [x] Add secondary storage support (Redis, etc.)
- [x] Implement session cleanup for expired sessions

## 5. Account Management (OAuth)

### 5.1 Domain Layer
- [x] Define Account entity for OAuth providers
- [x] Create AccountRepository interface
- [x] Add account linking business rules

### 5.2 OAuth Integration
- [x] Implement OAuth flow handlers for each provider (Google, GitHub, Discord)
- [x] Add OAuth token encryption/decryption
- [x] Create account linking functionality
- [x] Implement provider data synchronization

## 6. Email & Password Authentication

### 6.1 Password Management
- [x] Implement secure password hashing (argon2)
- [x] Add custom password hashing support
- [x] Create password verification utilities

### 6.2 Authentication Flow
- [x] Implement sign up usecase with email verification
- [x] Implement sign in usecase
- [x] Add password reset functionality
- [x] Implement automatic sign in after verification

### 6.3 Security Features
- [ ] Add brute force protection
- [ ] Implement account lockout mechanisms
- [ ] Add password strength validation

## 7. Social Authentication Providers

### 7.1 OAuth Handlers
- [x] Implement Google OAuth provider
- [x] Implement GitHub OAuth provider
- [x] Implement Discord OAuth provider
- [x] Add extensible provider interface for custom providers

### 7.2 OAuth Flow
- [x] Create OAuth authorization URL generation
- [x] Implement OAuth callback handling
- [x] Add state parameter validation for CSRF protection
- [x] Handle OAuth token exchange and user creation

## 8. Email Verification System

### 8.1 Token Management
- [x] Implement verification token generation
- [x] Add token expiration handling
- [x] Create secure token storage

### 8.2 Email Integration
- [ ] Define email sending interface
- [ ] Implement email verification sending
- [ ] Add email template system
- [ ] Create verification endpoint handlers

### 8.3 Verification Flow
- [x] Implement token verification usecase
- [x] Add automatic sign in after verification
- [x] Create verification cleanup for expired tokens

## 9. Rate Limiting

### 9.1 Rate Limit Engine
- [x] Implement in-memory rate limiting
- [x] Add database-backed rate limiting
- [ ] Create sliding window algorithm
- [x] Add custom rules support

### 9.2 Middleware
- [x] Create rate limiting HTTP middleware
- [x] Add IP-based tracking
- [x] Implement request throttling
- [x] Add rate limit headers to responses

## 10. Security & Advanced Features

### 10.1 Cookie Management
- [ ] Implement secure cookie handling
- [ ] Add cross-subdomain cookie support
- [ ] Create custom cookie attributes
- [ ] Add cookie prefix support

### 10.2 CSRF Protection
- [ ] Implement CSRF token generation
- [ ] Add CSRF validation middleware
- [ ] Create trusted origins checking

### 10.3 IP Tracking
- [ ] Add IP address extraction from headers
- [ ] Implement IP-based features (rate limiting, session tracking)
- [ ] Add IP geolocation support (optional)

## 11. Plugins System

### 11.1 Plugin Interface
- [ ] Define Plugin interface
- [ ] Implement plugin loading mechanism
- [ ] Add plugin initialization lifecycle
- [ ] Create plugin registry

### 11.2 Plugin Management
- [ ] Add plugin configuration validation
- [ ] Implement plugin dependency management
- [ ] Create plugin execution hooks

## 12. Hooks System

### 12.1 Database Hooks
- [ ] Implement before/after hooks for CRUD operations
- [ ] Add hooks for User, Session, Account, Verification models
- [ ] Create hook execution context

### 12.2 Request Lifecycle Hooks
- [ ] Implement before/after request hooks
- [ ] Add request context passing
- [ ] Create hook error handling

## 13. Error Handling & Logging

### 13.1 Logging System
- [x] Implement structured logging with slog
- [ ] Add configurable log levels
- [ ] Create request context logging
- [ ] Add color control for console output

### 13.2 Error Handling
- [x] Define custom error types
- [x] Implement error wrapping and chaining
- [x] Add API error responses
- [ ] Create custom error handlers

### 13.3 Observability
- [ ] Add OpenTelemetry integration
- [ ] Implement metrics collection
- [ ] Create health check endpoints

## 14. HTTP Handlers & API

### 14.1 Core Handlers
- [x] Implement authentication endpoints (/sign-in, /sign-up, /sign-out)
- [x] Add OAuth provider endpoints
- [x] Create verification endpoints
- [x] Implement session management endpoints

### 14.2 Middleware Stack
- [x] Create authentication middleware (with optional auth variant)
- [x] Add context utilities for user ID and token extraction
- [x] Add CORS middleware
- [x] Implement rate limiting middleware
- [ ] Add logging middleware

### 14.3 API Design
- [x] Design RESTful API endpoints
- [ ] Add OpenAPI/Swagger documentation
- [x] Implement consistent response formats
- [x] Create error response standardization

## 15. Testing & Quality Assurance

### 15.1 Unit Tests
- [x] Write unit tests for all domain logic
- [x] Add usecase layer testing
- [x] Create repository interface testing
- [x] Implement handler testing

### 15.2 Integration Tests
- [ ] Add database integration tests
- [ ] Implement end-to-end API tests
- [ ] Create OAuth flow testing
- [ ] Add email sending tests

### 15.3 Test Infrastructure
- [ ] Set up test database fixtures
- [ ] Create mock implementations for external services
- [ ] Add test utilities and helpers
- [ ] Implement CI/CD pipeline

## 16. Documentation & Examples

### 16.1 API Documentation
- [ ] Generate OpenAPI specifications
- [ ] Create API usage examples
- [ ] Add endpoint documentation
- [ ] Implement interactive API documentation

### 16.2 Library Documentation
- [ ] Write comprehensive README
- [ ] Create getting started guides
- [ ] Add configuration examples
- [ ] Document advanced features

### 16.3 Examples
- [ ] Create basic authentication example
- [ ] Add social login example
- [ ] Implement custom provider example
- [ ] Create full-stack integration examples

## 17. Deployment & Production

### 17.1 Docker Support
- [ ] Create Dockerfile for the library
- [ ] Add docker-compose for development
- [ ] Implement production Docker images
- [ ] Add Kubernetes deployment manifests

### 17.2 Configuration Management
- [ ] Add environment-specific configurations
- [ ] Implement configuration validation for production
- [ ] Create configuration migration tools
- [ ] Add secrets management integration

### 17.3 Monitoring & Maintenance
- [ ] Implement health checks
- [ ] Add metrics endpoints
- [ ] Create database migration tools
- [ ] Add backup and recovery procedures
