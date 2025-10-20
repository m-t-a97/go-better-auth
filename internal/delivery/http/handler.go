package http

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/internal/usecase"
	"github.com/m-t-a97/go-better-auth/pkg/csrf"
	"github.com/m-t-a97/go-better-auth/pkg/ratelimit"
)

// Handler represents the HTTP handler
type Handler struct {
	authUseCase  *usecase.AuthUseCase
	oauthUseCase *usecase.OAuthUseCase
	mfaUseCase   *usecase.MFAUseCase
	csrfManager  *csrf.Manager
	rateLimiter  domain.RateLimiter
	rateLimiters map[string]*ratelimit.Middleware
}

// NewHandler creates a new HTTP handler
func NewHandler(authUseCase *usecase.AuthUseCase, oauthUseCase *usecase.OAuthUseCase) *Handler {
	return &Handler{
		authUseCase:  authUseCase,
		oauthUseCase: oauthUseCase,
		rateLimiters: make(map[string]*ratelimit.Middleware),
	}
}

// NewHandlerWithMFA creates a new HTTP handler with MFA support
func NewHandlerWithMFA(authUseCase *usecase.AuthUseCase, oauthUseCase *usecase.OAuthUseCase, mfaUseCase *usecase.MFAUseCase) *Handler {
	return &Handler{
		authUseCase:  authUseCase,
		oauthUseCase: oauthUseCase,
		mfaUseCase:   mfaUseCase,
		rateLimiters: make(map[string]*ratelimit.Middleware),
	}
}

// NewHandlerWithCSRF creates a new HTTP handler with CSRF protection
func NewHandlerWithCSRF(authUseCase *usecase.AuthUseCase, oauthUseCase *usecase.OAuthUseCase, csrfManager *csrf.Manager) *Handler {
	return &Handler{
		authUseCase:  authUseCase,
		oauthUseCase: oauthUseCase,
		csrfManager:  csrfManager,
		rateLimiters: make(map[string]*ratelimit.Middleware),
	}
}

// NewHandlerWithCSRFAndMFA creates a new HTTP handler with CSRF and MFA support
func NewHandlerWithCSRFAndMFA(authUseCase *usecase.AuthUseCase, oauthUseCase *usecase.OAuthUseCase, csrfManager *csrf.Manager, mfaUseCase *usecase.MFAUseCase) *Handler {
	return &Handler{
		authUseCase:  authUseCase,
		oauthUseCase: oauthUseCase,
		csrfManager:  csrfManager,
		mfaUseCase:   mfaUseCase,
		rateLimiters: make(map[string]*ratelimit.Middleware),
	}
}

// SetRateLimiter sets the rate limiter for the handler
func (h *Handler) SetRateLimiter(limiter domain.RateLimiter) {
	h.rateLimiter = limiter
}

// AddRateLimitMiddleware adds a named rate limit middleware
func (h *Handler) AddRateLimitMiddleware(name string, middleware *ratelimit.Middleware) {
	if h.rateLimiters == nil {
		h.rateLimiters = make(map[string]*ratelimit.Middleware)
	}
	h.rateLimiters[name] = middleware
}

// SetupRouter sets up the HTTP router
func (h *Handler) SetupRouter() *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Add CSRF middleware if manager is configured
	if h.csrfManager != nil {
		csrfMiddleware := csrf.NewMiddleware(h.csrfManager)
		r.Use(csrfMiddleware.Handler)
	}

	// Auth routes
	r.Route("/api/auth", func(r chi.Router) {
		// Email & Password - apply auth rate limiting if available
		if authLimiter, ok := h.rateLimiters["auth"]; ok {
			r.Post("/sign-up/email", wrapHandler(authLimiter.Handler(http.HandlerFunc(h.SignUpEmail))))
			r.Post("/sign-in/email", wrapHandler(authLimiter.Handler(http.HandlerFunc(h.SignInEmail))))
		} else {
			r.Post("/sign-up/email", h.SignUpEmail)
			r.Post("/sign-in/email", h.SignInEmail)
		}

		r.Post("/sign-out", h.SignOut)

		// Session
		r.Get("/session", h.GetSession)
		r.Post("/session/refresh", h.RefreshSession)

		// Email verification
		if emailLimiter, ok := h.rateLimiters["email"]; ok {
			r.Post("/send-verification-email", wrapHandler(emailLimiter.Handler(http.HandlerFunc(h.SendVerificationEmail))))
		} else {
			r.Post("/send-verification-email", h.SendVerificationEmail)
		}
		r.Get("/verify-email", h.VerifyEmail)

		// Password reset - apply sensitive rate limiting if available
		if sensitiveLimit, ok := h.rateLimiters["sensitive"]; ok {
			r.Post("/request-password-reset", wrapHandler(sensitiveLimit.Handler(http.HandlerFunc(h.RequestPasswordReset))))
			r.Post("/reset-password", wrapHandler(sensitiveLimit.Handler(http.HandlerFunc(h.ResetPassword))))
			r.Post("/change-password", wrapHandler(sensitiveLimit.Handler(h.AuthMiddleware(h.ChangePassword))))
		} else {
			r.Post("/request-password-reset", h.RequestPasswordReset)
			r.Post("/reset-password", h.ResetPassword)
			r.Post("/change-password", h.AuthMiddleware(h.ChangePassword))
		}

		// OAuth
		r.Get("/oauth/{provider}", h.OAuthAuthorize)
		r.Get("/oauth/{provider}/callback", h.OAuthCallback)
		r.With(h.SessionAuthMiddleware).Post("/oauth/{provider}/refresh", h.OAuthRefreshToken)

		// MFA routes (only if MFA use case is configured)
		if h.mfaUseCase != nil {
			r.Route("/mfa", func(r chi.Router) {
				r.Use(h.SessionAuthMiddleware)
				mfaHandler := NewMFAHandler(h.mfaUseCase)

				// TOTP - apply MFA rate limiting if available
				if mfaLimiter, ok := h.rateLimiters["mfa"]; ok {
					r.Post("/totp/enable", wrapHandler(mfaLimiter.Handler(http.HandlerFunc(mfaHandler.EnableTOTP))))
					r.Post("/totp/verify", wrapHandler(mfaLimiter.Handler(http.HandlerFunc(mfaHandler.VerifyTOTPSetup))))
					r.Post("/totp/disable", wrapHandler(mfaLimiter.Handler(http.HandlerFunc(mfaHandler.DisableTOTP))))
					r.Post("/verify", wrapHandler(mfaLimiter.Handler(http.HandlerFunc(mfaHandler.VerifyMFACode))))
				} else {
					r.Post("/totp/enable", mfaHandler.EnableTOTP)
					r.Post("/totp/verify", mfaHandler.VerifyTOTPSetup)
					r.Post("/totp/disable", mfaHandler.DisableTOTP)
					r.Post("/verify", mfaHandler.VerifyMFACode)
				}

				// Status
				r.Get("/status", mfaHandler.GetMFAStatus)
			})
		}
	})

	return r
}

// AuthMiddleware validates the session token (works with http.HandlerFunc)
func (h *Handler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			respondError(w, domain.ErrInvalidToken)
			return
		}

		session, user, err := h.authUseCase.GetSession(r.Context(), token)
		if err != nil {
			respondError(w, err)
			return
		}

		// Add to context
		ctx := context.WithValue(r.Context(), "session", session)
		ctx = context.WithValue(ctx, "user", user)

		next(w, r.WithContext(ctx))
	}
}

// SessionAuthMiddleware is a framework-agnostic middleware that validates sessions (works with http.Handler)
func (h *Handler) SessionAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			respondError(w, domain.ErrInvalidToken)
			return
		}

		session, user, err := h.authUseCase.GetSession(r.Context(), token)
		if err != nil {
			respondError(w, err)
			return
		}

		// Add to context
		ctx := context.WithValue(r.Context(), "session", session)
		ctx = context.WithValue(ctx, "user", user)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CORSMiddleware provides CORS support
func (h *Handler) CORSMiddleware(next http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})(next)
}

// SignUpEmail handles email signup
func (h *Handler) SignUpEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string  `json:"email"`
		Password string  `json:"password"`
		Name     string  `json:"name"`
		Image    *string `json:"image"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.Name == "" {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	output, err := h.authUseCase.SignUpEmail(r.Context(), &usecase.SignUpEmailInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
		Image:    req.Image,
	})

	if err != nil {
		respondError(w, err)
		return
	}

	response := map[string]interface{}{
		"user": output.User,
	}

	if output.Session != nil {
		response["session"] = output.Session
		setSessionCookie(w, output.Session.Token)
	}

	respondJSON(w, http.StatusCreated, response)
}

// SignInEmail handles email signin
func (h *Handler) SignInEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		RememberMe bool   `json:"rememberMe"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	output, err := h.authUseCase.SignInEmail(r.Context(), &usecase.SignInEmailInput{
		Email:      req.Email,
		Password:   req.Password,
		RememberMe: req.RememberMe,
		IPAddress:  &ipAddress,
		UserAgent:  &userAgent,
	})

	if err != nil {
		respondError(w, err)
		return
	}

	setSessionCookie(w, output.Session.Token)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user":    output.User,
		"session": output.Session,
	})
}

// GetSession retrieves the current session
func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	session, user, err := h.authUseCase.GetSession(r.Context(), token)
	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user":    user,
		"session": session,
	})
}

// RefreshSession extends the expiration of the current session
func (h *Handler) RefreshSession(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	output, err := h.authUseCase.RefreshSession(r.Context(), &usecase.RefreshSessionInput{
		Token: token,
	})

	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user":    output.User,
		"session": output.Session,
	})
}

// SignOut handles user signout
func (h *Handler) SignOut(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	if err := h.authUseCase.SignOut(r.Context(), token); err != nil {
		respondError(w, err)
		return
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "better-auth.session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

// SendVerificationEmail sends a verification email
func (h *Handler) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if req.Email == "" {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if err := h.authUseCase.SendVerificationEmail(r.Context(), req.Email); err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

// VerifyEmail verifies an email address
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	user, err := h.authUseCase.VerifyEmail(r.Context(), token)
	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user": user,
	})
}

// RequestPasswordReset requests a password reset
func (h *Handler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if req.Email == "" {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if err := h.authUseCase.RequestPasswordReset(r.Context(), req.Email); err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

// ResetPassword resets a password
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if err := h.authUseCase.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

// ChangePassword changes a user's password
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	var req struct {
		CurrentPassword     string `json:"currentPassword"`
		NewPassword         string `json:"newPassword"`
		RevokeOtherSessions bool   `json:"revokeOtherSessions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	if err := h.authUseCase.ChangePassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword, req.RevokeOtherSessions); err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

// OAuthAuthorize redirects to OAuth provider
func (h *Handler) OAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	if state == "" {
		state = generateState()
	}

	authURL, err := h.oauthUseCase.GetAuthURL(provider, state, redirectURI)
	if err != nil {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// OAuthCallback handles OAuth callback
func (h *Handler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	code := r.URL.Query().Get("code")
	redirectURI := r.URL.Query().Get("redirect_uri")

	if code == "" {
		respondError(w, domain.ErrInvalidRequest)
		return
	}

	output, err := h.oauthUseCase.HandleCallback(r.Context(), provider, code, redirectURI)
	if err != nil {
		respondError(w, err)
		return
	}

	setSessionCookie(w, output.Session.Token)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user":    output.User,
		"session": output.Session,
	})
}

// OAuthRefreshToken refreshes an OAuth access token
func (h *Handler) OAuthRefreshToken(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")

	// Get user from context (requires session auth)
	user, ok := r.Context().Value("user").(*domain.User)
	if !ok {
		respondError(w, domain.ErrInvalidToken)
		return
	}

	output, err := h.oauthUseCase.RefreshToken(r.Context(), &usecase.RefreshTokenInput{
		UserID:   user.ID,
		Provider: provider,
	})

	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"accessToken":  output.AccessToken,
		"refreshToken": output.RefreshToken,
		"idToken":      output.IDToken,
		"expiresIn":    output.ExpiresIn,
	})
}

// Helper functions

func extractToken(r *http.Request) string {
	// Try cookie first
	cookie, err := r.Cookie("better-auth.session_token")
	if err == nil {
		return cookie.Value
	}

	// Try Authorization header
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "better-auth.session_token",
		Value:    token,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60, // 7 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func getIPAddress(r *http.Request) string {
	// Try X-Forwarded-For header first
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	// Try X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

func generateState() string {
	return usecase.GenerateToken()
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, err error) {
	authErr, ok := err.(*domain.AuthError)
	if !ok {
		authErr = &domain.AuthError{
			Code:    "internal_error",
			Message: err.Error(),
			Status:  http.StatusInternalServerError,
		}
	}

	respondJSON(w, authErr.Status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    authErr.Code,
			"message": authErr.Message,
		},
	})
}

// wrapHandler converts http.Handler to http.HandlerFunc for chi router compatibility
func wrapHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}
}
