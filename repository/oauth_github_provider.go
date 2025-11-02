package repository

import (
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
)

// GitHubOAuthProvider implements account.OAuthProvider for GitHub OAuth
type GitHubOAuthProvider struct {
	*BaseOAuthProvider
}

// NewGitHubOAuthProvider creates a new GitHub OAuth provider
func NewGitHubOAuthProvider(clientID, clientSecret, redirectURI string) (*GitHubOAuthProvider, error) {
	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return nil, fmt.Errorf("clientID, clientSecret, and redirectURI cannot be empty")
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes: []string{
			"user:email",
			"read:user",
		},
		Endpoint: github.Endpoint,
	}

	base := NewBaseOAuthProvider(account.ProviderGitHub, config, "https://api.github.com/user")

	return &GitHubOAuthProvider{
		BaseOAuthProvider: base,
	}, nil
}

// parseUserData parses GitHub user data
func (gp *GitHubOAuthProvider) parseUserData(data map[string]interface{}) *account.OAuthUser {
	user := gp.BaseOAuthProvider.parseUserData(data)

	// GitHub uses 'login' as identifier if 'id' is numeric
	if login, ok := data["login"].(string); ok && login != "" && user.ID == "" {
		user.ID = login
	}

	// GitHub-specific field mapping
	if avatarURL, ok := data["avatar_url"].(string); ok && avatarURL != "" {
		user.Picture = &avatarURL
	}

	return user
}
