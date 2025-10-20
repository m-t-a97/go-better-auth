package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	gobetterauth "github.com/m-t-a97/go-better-auth"
	"github.com/m-t-a97/go-better-auth/sessionauth"
)

// Example: How to use session auth middleware with Chi router
//
// This example demonstrates:
// 1. Initializing go-better-auth with a session auth middleware
// 2. Protecting routes with optional authentication (user info available but not required)
// 3. Protecting routes with required authentication (returns 401 if not authenticated)
// 4. Accessing authenticated user information from request context

func exampleSessionAuth() {
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

	// Create your router
	router := chi.NewRouter()

	// Add your framework-specific middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Mount the go-better-auth handler
	router.Mount("/api/auth", auth.Handler())

	// Create session auth middleware - two approaches:

	// APPROACH 1: Using convenience functions
	// This is the simplest for most use cases
	authMiddleware := auth.SessionAuth()

	// APPROACH 2: Using the sessionauth package directly
	// This gives you more control
	// sessionRepo, userRepo, _, _ := auth.Repositories()
	// authMiddleware := sessionauth.NewMiddleware(sessionRepo, userRepo).WithCookieName("custom-session")

	// Apply optional authentication middleware to all routes
	// This will attach user info if a valid session exists, but won't block unauthenticated requests
	router.Use(authMiddleware.Handler)

	// === Public Routes ===
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","message":"public route"}`))
	})

	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// === Routes with Optional Authentication ===
	// These routes work for both authenticated and unauthenticated users
	// The handler checks if a user is authenticated

	router.Get("/api/posts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check if user is authenticated
		user := sessionauth.GetUser(r.Context())

		if user != nil {
			// User is authenticated - show personalized content
			w.Write([]byte(`{"posts":[{"id":"1","title":"My Post","author":"` + user.Email + `"}]}`))
		} else {
			// User is not authenticated - show public content
			w.Write([]byte(`{"posts":[{"id":"1","title":"Public Post","author":"anonymous"}]}`))
		}
	})

	router.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		user := sessionauth.GetUser(r.Context())

		if user == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Please log in to view your profile"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id":"` + user.ID + `",
			"name":"` + user.Name + `",
			"email":"` + user.Email + `",
			"created_at":"` + user.CreatedAt.String() + `"
		}`))
	})

	// === Routes with Required Authentication ===
	// These routes return 401 if the user is not authenticated

	router.Route("/api/user", func(r chi.Router) {
		r.Use(authMiddleware.Require)

		r.Post("/settings", func(w http.ResponseWriter, r *http.Request) {
			user := sessionauth.GetUser(r.Context())
			// User is guaranteed to be non-nil here because we used authMiddleware.Require
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Settings updated for user ` + user.ID + `"}`))
		})

		r.Post("/profile", func(w http.ResponseWriter, r *http.Request) {
			user := sessionauth.GetUser(r.Context())
			session := sessionauth.GetSession(r.Context())

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"message":"Profile updated",
				"user_id":"` + user.ID + `",
				"session_expires_at":"` + session.ExpiresAt.String() + `"
			}`))
		})

		r.Delete("/sessions", func(w http.ResponseWriter, r *http.Request) {
			user := sessionauth.GetUser(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"All sessions for user ` + user.ID + ` have been deleted"}`))
		})
	})

	// === Using Middleware with Routes ===
	// You can also apply middleware to specific routes

	router.Route("/api/admin", func(r chi.Router) {
		// Apply required auth middleware to all admin routes
		r.Use(authMiddleware.Require)

		r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
			user := sessionauth.GetUser(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Welcome to admin dashboard, ` + user.Name + `"}`))
		})

		r.Get("/users", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"users":[]}`))
		})
	})

	// === Testing Routes ===
	// These are helper routes to test authentication flow

	router.Get("/api/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Multiple ways to check authentication
		if sessionauth.IsAuthenticated(r.Context()) {
			user := sessionauth.GetUser(r.Context())
			userID := sessionauth.GetUserID(r.Context())

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"authenticated":true,
				"user_id":"` + userID + `",
				"email":"` + user.Email + `"
			}`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"authenticated":false}`))
		}
	})

	log.Println("Starting server on http://localhost:3000")
	log.Println("")
	log.Println("Authentication endpoints:")
	log.Println("  POST http://localhost:3000/api/auth/sign-up/email")
	log.Println("  POST http://localhost:3000/api/auth/sign-in/email")
	log.Println("  POST http://localhost:3000/api/auth/sign-out")
	log.Println("")
	log.Println("Public routes (unauthenticated):")
	log.Println("  GET http://localhost:3000/")
	log.Println("  GET http://localhost:3000/health")
	log.Println("")
	log.Println("Optional auth routes (works with or without authentication):")
	log.Println("  GET http://localhost:3000/api/posts")
	log.Println("  GET http://localhost:3000/api/profile")
	log.Println("  GET http://localhost:3000/api/me")
	log.Println("")
	log.Println("Protected routes (requires authentication):")
	log.Println("  POST http://localhost:3000/api/user/settings")
	log.Println("  POST http://localhost:3000/api/user/profile")
	log.Println("  DELETE http://localhost:3000/api/user/sessions")
	log.Println("")
	log.Println("Admin routes (requires authentication):")
	log.Println("  GET http://localhost:3000/api/admin/dashboard")
	log.Println("  GET http://localhost:3000/api/admin/users")
	log.Println("")

	log.Fatal(http.ListenAndServe(":3000", router))
}
