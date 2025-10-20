package examples

import (
	"github.com/m-t-a97/go-better-auth/pkg/gobetterauth"
)

// SetupFiberServer demonstrates how to integrate Go Better Auth with Fiber framework
// Fiber provides middleware wrappers to convert http.Handler and http.HandlerFunc
//
// Usage example:
//
//	import "github.com/gofiber/fiber/v3"
//	import "github.com/gofiber/fiber/v3/middleware/adaptor"
//
//	app := fiber.New()
//	handlers := auth.GetHandlers()
//	middlewares := auth.GetMiddleware()
//
//	// Public routes
//	app.Post("/api/auth/sign-up/email", adaptor.HTTPHandler(handlers.SignUpEmail))
//	app.Post("/api/auth/sign-in/email", adaptor.HTTPHandler(handlers.SignInEmail))
//	app.Get("/api/auth/verify-email", adaptor.HTTPHandler(handlers.VerifyEmail))
//	app.Post("/api/auth/request-password-reset", adaptor.HTTPHandler(handlers.RequestPasswordReset))
//	app.Post("/api/auth/reset-password", adaptor.HTTPHandler(handlers.ResetPassword))
//
//	// OAuth routes
//	app.Get("/api/auth/oauth/:provider", adaptor.HTTPHandler(handlers.OAuthAuthorize))
//	app.Get("/api/auth/oauth/:provider/callback", adaptor.HTTPHandler(handlers.OAuthCallback))
//
//	// Protected routes with middleware
//	protected := app.Group("/api/auth")
//	protected.Use(adaptor.HTTPMiddleware(middlewares.SessionAuth))
//	{
//	    protected.Get("/session", adaptor.HTTPHandler(handlers.GetSession))
//	    protected.Post("/sign-out", adaptor.HTTPHandler(handlers.SignOut))
//	    protected.Post("/change-password", adaptor.HTTPHandler(handlers.ChangePassword))
//	    protected.Post("/send-verification-email", adaptor.HTTPHandler(handlers.SendVerificationEmail))
//	}
func SetupFiberServer(auth *gobetterauth.GoBetterAuth) {
	// Get handlers and middleware from Go Better Auth
	handlers := auth.GetHandlers()
	middlewares := auth.GetMiddleware()

	// All handlers are http.HandlerFunc, so they can be directly wrapped with adaptor.HTTPHandler()
	_ = handlers
	_ = middlewares

	// Example code (requires "github.com/gofiber/fiber/v3" and "github.com/gofiber/fiber/v3/middleware/adaptor"):
	/*
		app := fiber.New()

		// Apply CORS middleware globally
		app.Use(adaptor.HTTPMiddleware(middlewares.CORS))

		// Public routes (no auth required)
		app.Post("/api/auth/sign-up/email", adaptor.HTTPHandler(handlers.SignUpEmail))
		app.Post("/api/auth/sign-in/email", adaptor.HTTPHandler(handlers.SignInEmail))
		app.Get("/api/auth/verify-email", adaptor.HTTPHandler(handlers.VerifyEmail))
		app.Post("/api/auth/request-password-reset", adaptor.HTTPHandler(handlers.RequestPasswordReset))
		app.Post("/api/auth/reset-password", adaptor.HTTPHandler(handlers.ResetPassword))

		// OAuth routes
		app.Get("/api/auth/oauth/:provider", adaptor.HTTPHandler(handlers.OAuthAuthorize))
		app.Get("/api/auth/oauth/:provider/callback", adaptor.HTTPHandler(handlers.OAuthCallback))

		// Protected routes (require auth middleware)
		protected := app.Group("/api/auth")
		protected.Use(adaptor.HTTPMiddleware(middlewares.SessionAuth))
		{
			protected.Get("/session", adaptor.HTTPHandler(handlers.GetSession))
			protected.Post("/sign-out", adaptor.HTTPHandler(handlers.SignOut))
			protected.Post("/change-password", adaptor.HTTPHandler(handlers.ChangePassword))
			protected.Post("/send-verification-email", adaptor.HTTPHandler(handlers.SendVerificationEmail))
		}

		log.Fatal(app.Listen(":8080"))
	*/
}
