package examples

import (
	"github.com/m-t-a97/go-better-auth/pkg/gobetterauth"
)

// SetupGinServer demonstrates how to integrate Go Better Auth with Gin framework
// Gin provides gin.WrapF and gin.WrapH functions to convert http.HandlerFunc and http.Handler
//
// Usage example:
//
//	import "github.com/gin-gonic/gin"
//
//	r := gin.Default()
//	handlers := auth.GetHandlers()
//	middlewares := auth.GetMiddleware()
//
//	// Public routes
//	r.POST("/api/auth/sign-up/email", gin.WrapF(handlers.SignUpEmail))
//	r.POST("/api/auth/sign-in/email", gin.WrapF(handlers.SignInEmail))
//	r.GET("/api/auth/verify-email", gin.WrapF(handlers.VerifyEmail))
//	r.POST("/api/auth/request-password-reset", gin.WrapF(handlers.RequestPasswordReset))
//	r.POST("/api/auth/reset-password", gin.WrapF(handlers.ResetPassword))
//
//	// OAuth routes
//	r.GET("/api/auth/oauth/:provider", gin.WrapF(handlers.OAuthAuthorize))
//	r.GET("/api/auth/oauth/:provider/callback", gin.WrapF(handlers.OAuthCallback))
//
//	// Protected routes with middleware
//	protected := r.Group("/api/auth")
//	protected.Use(gin.WrapH(middlewares.SessionAuth))
//	{
//	    protected.GET("/session", gin.WrapF(handlers.GetSession))
//	    protected.POST("/sign-out", gin.WrapF(handlers.SignOut))
//	    protected.POST("/change-password", gin.WrapF(handlers.ChangePassword))
//	    protected.POST("/send-verification-email", gin.WrapF(handlers.SendVerificationEmail))
//	}
func SetupGinServer(auth *gobetterauth.GoBetterAuth) {
	// Get handlers and middleware from Go Better Auth
	handlers := auth.GetHandlers()
	middlewares := auth.GetMiddleware()

	// All handlers are http.HandlerFunc, so they can be directly wrapped with gin.WrapF()
	_ = handlers
	_ = middlewares

	// Example code (requires "github.com/gin-gonic/gin"):
	/*
		r := gin.Default()

		// Apply CORS middleware globally
		r.Use(gin.WrapH(middlewares.CORS))

		// Public routes (no auth required)
		r.POST("/api/auth/sign-up/email", gin.WrapF(handlers.SignUpEmail))
		r.POST("/api/auth/sign-in/email", gin.WrapF(handlers.SignInEmail))
		r.GET("/api/auth/verify-email", gin.WrapF(handlers.VerifyEmail))
		r.POST("/api/auth/request-password-reset", gin.WrapF(handlers.RequestPasswordReset))
		r.POST("/api/auth/reset-password", gin.WrapF(handlers.ResetPassword))

		// OAuth routes
		r.GET("/api/auth/oauth/:provider", gin.WrapF(handlers.OAuthAuthorize))
		r.GET("/api/auth/oauth/:provider/callback", gin.WrapF(handlers.OAuthCallback))

		// Protected routes (require auth middleware)
		protected := r.Group("/api/auth")
		protected.Use(gin.WrapH(middlewares.SessionAuth))
		{
			protected.GET("/session", gin.WrapF(handlers.GetSession))
			protected.POST("/sign-out", gin.WrapF(handlers.SignOut))
			protected.POST("/change-password", gin.WrapF(handlers.ChangePassword))
			protected.POST("/send-verification-email", gin.WrapF(handlers.SendVerificationEmail))
		}

		log.Fatal(r.Run(":8080"))
	*/
}
