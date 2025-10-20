package examples

import (
	"github.com/go-chi/chi/v5"

	"github.com/m-t-a97/go-better-auth/pkg/gobetterauth"
)

// SetupChiServer demonstrates how to integrate Go Better Auth with Chi framework
func SetupChiServer(auth *gobetterauth.GoBetterAuth) *chi.Mux {
	r := chi.NewMux()

	// Get handlers and middleware from Go Better Auth
	handlers := auth.GetHandlers()
	middlewares := auth.GetMiddleware()

	// Create a wrapper to convert http.HandlerFunc to chi routes
	// Chi can directly use http.HandlerFunc

	// Public routes (no auth required)
	r.Post("/api/auth/sign-up/email", handlers.SignUpEmail)
	r.Post("/api/auth/sign-in/email", handlers.SignInEmail)
	r.Post("/api/auth/verify-email", handlers.VerifyEmail)
	r.Post("/api/auth/request-password-reset", handlers.RequestPasswordReset)
	r.Post("/api/auth/reset-password", handlers.ResetPassword)

	// OAuth routes
	r.Get("/api/auth/oauth/authorize", handlers.OAuthAuthorize)
	r.Get("/api/auth/oauth/callback", handlers.OAuthCallback)

	// Protected routes (require auth middleware)
	r.Route("/api/auth", func(protected chi.Router) {
		protected.Use(middlewares.SessionAuth)
		protected.Get("/session", handlers.GetSession)
		protected.Post("/sign-out", handlers.SignOut)
		protected.Post("/change-password", handlers.ChangePassword)
		protected.Post("/send-verification-email", handlers.SendVerificationEmail)
	})

	return r
}

// // Example usage - uncomment to run
// func main() {
// 	config := &gobetterauth.Config{
// 		BaseURL: "http://localhost:8080",
// 		Database: gobetterauth.DatabaseConfig{
// 			Provider:         "postgres",
// 			ConnectionString: "postgres://user:password@localhost:5432/gobetterauth",
// 		},
// 		Session: gobetterauth.SessionConfig{
// 			ExpiresIn:    7 * 24 * time.Hour,
// 			CookieName:   "auth_session",
// 			CookieSecure: false, // Set to true in production with HTTPS
// 		},
// 		EmailAndPassword: gobetterauth.EmailPasswordConfig{
// 			Enabled:    true,
// 			AutoSignIn: true,
// 		},
// 	}

// 	auth, err := gobetterauth.New(config)
// 	if err != nil {
// 		log.Fatalf("Failed to initialize Go Better Auth: %v", err)
// 	}

// 	r := SetupChiServer(auth)
// 	log.Fatal(http.ListenAndServe(":8080", r))
// }
