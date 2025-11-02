package repository

import (
	"fmt"

	"golang.org/x/oauth2"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
)

var discordEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/api/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

// DiscordOAuthProvider implements account.OAuthProvider for Discord OAuth
type DiscordOAuthProvider struct {
	*BaseOAuthProvider
}

// NewDiscordOAuthProvider creates a new Discord OAuth provider
func NewDiscordOAuthProvider(clientID, clientSecret, redirectURI string) (*DiscordOAuthProvider, error) {
	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return nil, fmt.Errorf("clientID, clientSecret, and redirectURI cannot be empty")
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes: []string{
			"identify",
			"email",
		},
		Endpoint: discordEndpoint,
	}

	base := NewBaseOAuthProvider(account.ProviderDiscord, config, "https://discord.com/api/users/@me")

	return &DiscordOAuthProvider{
		BaseOAuthProvider: base,
	}, nil
}

// parseUserData parses Discord user data
func (dp *DiscordOAuthProvider) parseUserData(data map[string]interface{}) *account.OAuthUser {
	user := dp.BaseOAuthProvider.parseUserData(data)

	// Discord-specific field mappings
	if userID, ok := data["id"].(string); ok && userID != "" {
		user.ID = userID
	}

	if username, ok := data["username"].(string); ok && username != "" && user.Name == "" {
		user.Name = username
	}

	// Build Discord CDN avatar URL
	if avatar, ok := data["avatar"].(string); ok && avatar != "" {
		if userID, ok := data["id"].(string); ok {
			avatarURL := "https://cdn.discordapp.com/avatars/" + userID + "/" + avatar + ".png"
			user.Picture = &avatarURL
		}
	}

	return user
}
