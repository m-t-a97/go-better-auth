package plugin

import (
	"net/http"

	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/internal/usecase"
)

// Plugin defines the interface for Go Better Auth plugins
type Plugin interface {
	// Name returns the plugin name
	Name() string

	// Initialize is called when the plugin is loaded
	Initialize(config *PluginConfig) error

	// RegisterRoutes registers HTTP routes for the plugin
	RegisterRoutes(router Router)

	// RegisterMiddleware registers middleware for the plugin
	RegisterMiddleware() []Middleware
}

// PluginConfig holds configuration passed to plugins
type PluginConfig struct {
	UserRepo         domain.UserRepository
	SessionRepo      domain.SessionRepository
	AccountRepo      domain.AccountRepository
	VerificationRepo domain.VerificationRepository
	AuthUseCase      *usecase.AuthUseCase
	BaseURL          string
}

// Router interface for registering routes
type Router interface {
	Get(pattern string, handler http.HandlerFunc)
	Post(pattern string, handler http.HandlerFunc)
	Put(pattern string, handler http.HandlerFunc)
	Delete(pattern string, handler http.HandlerFunc)
}

// Middleware represents HTTP middleware
type Middleware func(http.Handler) http.Handler

// BasePlugin provides a base implementation of Plugin
type BasePlugin struct {
	name string
}

func (p *BasePlugin) Name() string {
	return p.name
}

func (p *BasePlugin) Initialize(config *PluginConfig) error {
	return nil
}

func (p *BasePlugin) RegisterRoutes(router Router) {
	// Default: no routes
}

func (p *BasePlugin) RegisterMiddleware() []Middleware {
	return nil
}

// Example: Two-Factor Authentication Plugin
type TwoFactorPlugin struct {
	BasePlugin
	config *PluginConfig
}

func NewTwoFactorPlugin() *TwoFactorPlugin {
	return &TwoFactorPlugin{
		BasePlugin: BasePlugin{name: "two-factor"},
	}
}

func (p *TwoFactorPlugin) Initialize(config *PluginConfig) error {
	p.config = config
	// Initialize 2FA logic here
	return nil
}

func (p *TwoFactorPlugin) RegisterRoutes(router Router) {
	router.Post("/api/auth/2fa/enable", p.handleEnable2FA)
	router.Post("/api/auth/2fa/verify", p.handleVerify2FA)
	router.Post("/api/auth/2fa/disable", p.handleDisable2FA)
}

func (p *TwoFactorPlugin) handleEnable2FA(w http.ResponseWriter, r *http.Request) {
	// Implementation for enabling 2FA
	w.WriteHeader(http.StatusOK)
}

func (p *TwoFactorPlugin) handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	// Implementation for verifying 2FA code
	w.WriteHeader(http.StatusOK)
}

func (p *TwoFactorPlugin) handleDisable2FA(w http.ResponseWriter, r *http.Request) {
	// Implementation for disabling 2FA
	w.WriteHeader(http.StatusOK)
}

// Example: Rate Limiting Plugin
type RateLimitPlugin struct {
	BasePlugin
	requestsPerMinute int
}

func NewRateLimitPlugin(requestsPerMinute int) *RateLimitPlugin {
	return &RateLimitPlugin{
		BasePlugin:        BasePlugin{name: "rate-limit"},
		requestsPerMinute: requestsPerMinute,
	}
}

func (p *RateLimitPlugin) RegisterMiddleware() []Middleware {
	return []Middleware{p.rateLimitMiddleware}
}

func (p *RateLimitPlugin) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rate limiting logic
		// This is a simplified example
		next.ServeHTTP(w, r)
	})
}
