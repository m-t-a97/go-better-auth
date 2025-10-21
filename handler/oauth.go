package handler

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"github.com/m-t-a97/go-better-auth/storage"
	"github.com/m-t-a97/go-better-auth/usecase/auth"
)

// OAuthHandler handles OAuth authentication endpoints
type OAuthHandler struct {
	service      *auth.Service
	stateManager *storage.OAuthStateManager
	providerReg  account.OAuthProviderRegistry
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(
	service *auth.Service,
	stateManager *storage.OAuthStateManager,
	providerReg account.OAuthProviderRegistry,
) *OAuthHandler {
	return &OAuthHandler{
		service:      service,
		stateManager: stateManager,
		providerReg:  providerReg,
	}
}

// OAuthAuthorizeRequest represents the query parameters for OAuth authorization
type OAuthAuthorizeRequest struct {
	// RedirectURI is where the user should be redirected after OAuth flow completes
	RedirectURI string `json:"redirect_uri"`
	// State is optional additional state to preserve through the OAuth flow
	State string `json:"state"`
}

// OAuthCallbackRequest represents the query parameters for OAuth callback
type OAuthCallbackRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
	Error string `json:"error"`
}

// HandleOAuthAuthorize initiates the OAuth authorization flow
// GET /auth/oauth/{provider}
func (h *OAuthHandler) HandleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract provider from URL path
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		ErrorResponse(w, http.StatusBadRequest, "provider not specified")
		return
	}
	providerID := account.ProviderType(parts[2])

	// Get provider from registry
	provider, err := h.providerReg.Get(providerID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get oauth provider",
			"provider", providerID,
			"error", err)
		ErrorResponse(w, http.StatusNotFound, "OAuth provider not configured")
		return
	}

	// Parse request parameters
	redirectURI := r.URL.Query().Get("redirect_uri")
	userState := r.URL.Query().Get("state")

	// Generate state parameter for CSRF protection
	state, err := h.stateManager.GenerateState(string(providerID), redirectURI, userState)
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate oauth state",
			"provider", providerID,
			"error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to generate OAuth state")
		return
	}

	// Get authorization URL from provider
	authURL, err := provider.GetAuthorizationURL(ctx, state)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get authorization URL",
			"provider", providerID,
			"error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to generate authorization URL")
		return
	}

	slog.InfoContext(ctx, "redirecting to oauth provider",
		"provider", providerID,
		"auth_url", authURL)

	// Redirect user to provider's authorization page
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleOAuthCallback handles the OAuth callback from the provider
// GET /auth/oauth/{provider}/callback
func (h *OAuthHandler) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract provider from URL path
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		ErrorResponse(w, http.StatusBadRequest, "provider not specified")
		return
	}
	providerID := account.ProviderType(parts[2])

	// Check for OAuth error response
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDescription := r.URL.Query().Get("error_description")
		slog.ErrorContext(ctx, "oauth provider returned error",
			"provider", providerID,
			"error", errMsg,
			"description", errDescription)
		ErrorResponse(w, http.StatusBadRequest, errDescription)
		return
	}

	// Get authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		ErrorResponse(w, http.StatusBadRequest, "authorization code missing")
		return
	}

	if state == "" {
		ErrorResponse(w, http.StatusBadRequest, "state parameter missing")
		return
	}

	// Validate state parameter
	stateData, err := h.stateManager.ValidateState(state)
	if err != nil {
		slog.ErrorContext(ctx, "invalid oauth state",
			"provider", providerID,
			"error", err)
		ErrorResponse(w, http.StatusBadRequest, "Invalid or expired OAuth state")
		return
	}

	// Verify provider matches
	if stateData.ProviderID != string(providerID) {
		slog.ErrorContext(ctx, "provider mismatch",
			"expected", stateData.ProviderID,
			"actual", providerID)
		ErrorResponse(w, http.StatusBadRequest, "OAuth provider mismatch")
		return
	}

	// Get provider from registry
	provider, err := h.providerReg.Get(providerID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get oauth provider",
			"provider", providerID,
			"error", err)
		ErrorResponse(w, http.StatusNotFound, "OAuth provider not configured")
		return
	}

	// Exchange authorization code for tokens
	tokens, err := provider.ExchangeCode(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "failed to exchange oauth code",
			"provider", providerID,
			"error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to exchange authorization code")
		return
	}

	// Get user info from provider
	oauthUser, err := provider.GetUser(ctx, tokens)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get oauth user info",
			"provider", providerID,
			"error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve user information")
		return
	}

	// Sign in or sign up the user
	signInReq := &auth.OAuthSignInRequest{
		ProviderID:  providerID,
		OAuthUser:   oauthUser,
		OAuthTokens: tokens,
	}

	signInResp, err := h.service.OAuthSignIn(ctx, signInReq)
	if err != nil {
		slog.ErrorContext(ctx, "oauth signin failed",
			"provider", providerID,
			"email", oauthUser.Email,
			"error", err)
		ErrorResponse(w, http.StatusInternalServerError, "OAuth sign-in failed")
		return
	}

	slog.InfoContext(ctx, "oauth signin successful",
		"provider", providerID,
		"user_id", signInResp.User.ID,
		"email", signInResp.User.Email,
		"is_new_user", signInResp.IsNewUser)

	// Redirect to the original redirect URI or default
	redirectURI := stateData.RedirectTo
	if redirectURI == "" {
		redirectURI = "/"
	}

	// Build response with token and redirect info
	SuccessResponse(w, http.StatusOK, map[string]interface{}{
		"token":       signInResp.Session.Token,
		"expires_at":  signInResp.Session.ExpiresAt,
		"user":        signInResp.User,
		"redirect_to": redirectURI,
		"is_new_user": signInResp.IsNewUser,
	})
}

// HandleOAuthUnlink unlinks an OAuth account from the user
// DELETE /auth/oauth/{provider}
func (h *OAuthHandler) HandleOAuthUnlink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get authenticated user from context
	userID, ok := ctx.Value("user_id").(string)
	if !ok || userID == "" {
		ErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Extract provider from URL path
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		ErrorResponse(w, http.StatusBadRequest, "provider not specified")
		return
	}
	providerID := account.ProviderType(parts[2])

	// Unlink the account
	req := &auth.UnlinkOAuthAccountRequest{
		UserID:     userID,
		ProviderID: providerID,
	}

	if _, err := h.service.UnlinkOAuthAccount(ctx, req); err != nil {
		slog.ErrorContext(ctx, "failed to unlink oauth account",
			"user_id", userID,
			"provider", providerID,
			"error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to unlink OAuth account")
		return
	}

	slog.InfoContext(ctx, "oauth account unlinked",
		"user_id", userID,
		"provider", providerID)

	SuccessResponse(w, http.StatusOK, map[string]interface{}{
		"message": "OAuth account unlinked successfully",
	})
}

// HandleOAuthLinkedAccounts returns all OAuth accounts linked to the user
// GET /auth/oauth/accounts
func (h *OAuthHandler) HandleOAuthLinkedAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get authenticated user from context
	userID, ok := ctx.Value("user_id").(string)
	if !ok || userID == "" {
		ErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get linked accounts
	accounts, err := h.service.GetLinkedAccounts(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get linked accounts",
			"user_id", userID,
			"error", err)
		ErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve linked accounts")
		return
	}

	SuccessResponse(w, http.StatusOK, map[string]interface{}{
		"accounts": accounts,
	})
}
