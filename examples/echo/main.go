package main

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	gobetterauth "github.com/m-t-a97/go-better-auth"
)

// Example: How to wrap go-better-auth native HTTP handler with Echo router
//
// go-better-auth provides a complete, framework-agnostic HTTP handler that implements
// all authentication endpoints. This example shows how to wrap it with Echo for additional
// middleware and routing features.
//
// The recommended approach:
// 1. Initialize go-better-auth with your config
// 2. Mount auth.Handler() on your router using your framework's mount/handle methods
// 3. (Optional) Add framework-specific middleware around it
//
// This architecture means:
// - go-better-auth handles ALL authentication logic
// - Your framework just provides routing and middleware
// - You're not duplicating HTTP handler code
// - Easy to migrate between frameworks - just change the mount point

func main() {
	// Initialize Go Better Auth with your configuration
	auth, err := gobetterauth.New(&gobetterauth.Config{
		Database: gobetterauth.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
		BaseURL: "http://localhost:3000",
		EmailAndPassword: gobetterauth.EmailPasswordConfig{
			Enabled:    true,
			AutoSignIn: true,
		},
		Session: gobetterauth.SessionConfig{
			ExpiresIn: 0, // Use default (7 days)
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize Go Better Auth: %v", err)
	}

	// Create your Echo router
	router := echo.New()

	// Add your framework-specific middleware
	router.Use(middleware.Logger())
	router.Use(middleware.Recover())
	router.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
	}))

	// Mount the go-better-auth handler - this is all you need!
	// All auth endpoints are now available:
	// POST /api/auth/sign-up/email
	// POST /api/auth/sign-in/email
	// POST /api/auth/sign-out
	// GET  /api/auth/session
	// POST /api/auth/send-verification-email
	// POST /api/auth/verify-email
	// POST /api/auth/request-password-reset
	// POST /api/auth/reset-password
	// POST /api/auth/change-password
	// GET  /api/auth/oauth/{provider}
	// And more...
	//
	// In Echo, we use a custom wrapper to adapt the http.Handler to Echo's Handler
	router.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))

	// Add your application-specific routes
	router.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	log.Println("Starting server on http://localhost:3000")
	log.Println("Try: POST http://localhost:3000/api/auth/sign-up/email")
	log.Fatal(router.Start(":3000"))
}
