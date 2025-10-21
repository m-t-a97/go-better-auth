package repository

import (
	"fmt"

	"github.com/m-t-a97/go-better-auth/domain/account"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleOAuthProvider implements account.OAuthProvider for Google OAuth
type GoogleOAuthProvider struct {
	*BaseOAuthProvider
}

// NewGoogleOAuthProvider creates a new Google OAuth provider
func NewGoogleOAuthProvider(clientID, clientSecret, redirectURI string) (*GoogleOAuthProvider, error) {
	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return nil, fmt.Errorf("clientID, clientSecret, and redirectURI cannot be empty")
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	base := NewBaseOAuthProvider(account.ProviderGoogle, config, "https://www.googleapis.com/oauth2/v2/userinfo")

	return &GoogleOAuthProvider{
		BaseOAuthProvider: base,
	}, nil
}

// parseUserData parses Google user data
func (gp *GoogleOAuthProvider) parseUserData(data map[string]interface{}) *account.OAuthUser {
	user := gp.BaseOAuthProvider.parseUserData(data)

	// Google-specific field mappings
	if picture, ok := data["picture"].(string); ok && picture != "" {
		user.Picture = &picture
	}

	// Google returns 'verified_email' field
	if verifiedEmail, ok := data["verified_email"].(bool); ok && verifiedEmail {
		// We might want to track this separately if needed
	}

	return user
}
