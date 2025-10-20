package examples

import (
	"github.com/m-t-a97/go-better-auth/pkg/gobetterauth"
)

// SetupEchoServer demonstrates how to integrate Go Better Auth with Echo framework
// Echo provides middleware wrappers to convert http.Handler and http.HandlerFunc
//
// Usage example:
//
//	import "github.com/labstack/echo/v4"
//	import "github.com/labstack/echo/v4/middleware"
//
//	e := echo.New()
//	handlers := auth.GetHandlers()
//	middlewares := auth.GetMiddleware()
//
//	// Public routes
//	e.POST("/api/auth/sign-up/email", echo.WrapHandler(handlers.SignUpEmail))
//	e.POST("/api/auth/sign-in/email", echo.WrapHandler(handlers.SignInEmail))
//	e.GET("/api/auth/verify-email", echo.WrapHandler(handlers.VerifyEmail))
//	e.POST("/api/auth/request-password-reset", echo.WrapHandler(handlers.RequestPasswordReset))
//	e.POST("/api/auth/reset-password", echo.WrapHandler(handlers.ResetPassword))
//
//	// OAuth routes
//	e.GET("/api/auth/oauth/:provider", echo.WrapHandler(handlers.OAuthAuthorize))
//	e.GET("/api/auth/oauth/:provider/callback", echo.WrapHandler(handlers.OAuthCallback))
//
//	// Protected routes with middleware
//	protected := e.Group("/api/auth")
//	protected.Use(echo.WrapMiddleware(middlewares.SessionAuth))
//	{
//	    protected.GET("/session", echo.WrapHandler(handlers.GetSession))
//	    protected.POST("/sign-out", echo.WrapHandler(handlers.SignOut))
//	    protected.POST("/change-password", echo.WrapHandler(handlers.ChangePassword))
//	    protected.POST("/send-verification-email", echo.WrapHandler(handlers.SendVerificationEmail))
//	}
func SetupEchoServer(auth *gobetterauth.GoBetterAuth) {
	// Get handlers and middleware from Go Better Auth
	handlers := auth.GetHandlers()
	middlewares := auth.GetMiddleware()

	// All handlers are http.HandlerFunc, so they can be directly wrapped with echo.WrapHandler()
	_ = handlers
	_ = middlewares

	// Example code (requires "github.com/labstack/echo/v4"):
	/*
		e := echo.New()

		// Apply CORS middleware globally
		e.Use(echo.WrapMiddleware(middlewares.CORS))

		// Public routes (no auth required)
		e.POST("/api/auth/sign-up/email", echo.WrapHandler(handlers.SignUpEmail))
		e.POST("/api/auth/sign-in/email", echo.WrapHandler(handlers.SignInEmail))
		e.GET("/api/auth/verify-email", echo.WrapHandler(handlers.VerifyEmail))
		e.POST("/api/auth/request-password-reset", echo.WrapHandler(handlers.RequestPasswordReset))
		e.POST("/api/auth/reset-password", echo.WrapHandler(handlers.ResetPassword))

		// OAuth routes
		e.GET("/api/auth/oauth/:provider", echo.WrapHandler(handlers.OAuthAuthorize))
		e.GET("/api/auth/oauth/:provider/callback", echo.WrapHandler(handlers.OAuthCallback))

		// Protected routes (require auth middleware)
		protected := e.Group("/api/auth")
		protected.Use(echo.WrapMiddleware(middlewares.SessionAuth))
		{
			protected.GET("/session", echo.WrapHandler(handlers.GetSession))
			protected.POST("/sign-out", echo.WrapHandler(handlers.SignOut))
			protected.POST("/change-password", echo.WrapHandler(handlers.ChangePassword))
			protected.POST("/send-verification-email", echo.WrapHandler(handlers.SendVerificationEmail))
		}

		log.Fatal(e.Start(":8080"))
	*/
}
