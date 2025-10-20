package examples

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/http/cookiejar"
	"time"

	_ "github.com/lib/pq"
	htthandler "github.com/m-t-a97/go-better-auth/internal/delivery/http"
	"github.com/m-t-a97/go-better-auth/internal/usecase"
	"github.com/m-t-a97/go-better-auth/pkg/csrf"
)

// ExampleCSRFIntegration demonstrates how to set up CSRF protection
// This example shows a complete setup with PostgreSQL storage
func ExampleCSRFIntegration() error {
	// 1. Connect to database
	db, err := sql.Open("postgres", "postgres://user:password@localhost/go_better_auth?sslmode=disable")
	if err != nil {
		return err
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		return err
	}

	// 2. Create CSRF repository
	csrfRepo := csrf.NewPostgresRepository(db)

	// Initialize schema (run once on application startup)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := csrfRepo.InitSchema(ctx); err != nil {
		log.Printf("Warning: Could not initialize CSRF schema: %v", err)
		// Schema might already exist, which is fine
	}

	// 3. Create CSRF manager
	// Use 15 minute TTL for tokens
	// Set secure=true for HTTPS, false for HTTP
	csrfManager := csrf.NewManager(csrfRepo, 15*time.Minute, true)

	// Note: You would also create your auth use cases and handler here
	// See pkg/gobetterauth/gobetterauth.go for full setup example

	// Create handler with CSRF protection (requires authUseCase and oauthUseCase)
	// handler := htthandler.NewHandlerWithCSRF(authUseCase, oauthUseCase, csrfManager)

	// Setup router
	// router := handler.SetupRouter()

	// 4. Optional: Setup periodic cleanup of expired tokens
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			if err := csrfManager.CleanupExpiredTokens(); err != nil {
				log.Printf("Error cleaning up expired CSRF tokens: %v", err)
			}
		}
	}()

	// 5. Start server (uncomment when using actual handler)
	// log.Println("Starting server with CSRF protection on :3000")
	// return http.ListenAndServe(":3000", router)

	log.Println("CSRF repository initialized successfully")
	return nil
}

// ExampleCSRFDevelopment demonstrates CSRF setup for development
// Uses in-memory storage (no database required)
func ExampleCSRFDevelopment(authUseCase *usecase.AuthUseCase, oauthUseCase *usecase.OAuthUseCase) http.Handler {
	// Use in-memory repository for development
	csrfRepo := csrf.NewInMemoryRepository()

	// Create CSRF manager with HTTP (not secure)
	csrfManager := csrf.NewManager(csrfRepo, 15*time.Minute, false)

	// Create handler with CSRF protection
	handler := htthandler.NewHandlerWithCSRF(authUseCase, oauthUseCase, csrfManager)

	// Return router
	return handler.SetupRouter()
}

// ExampleClientCode shows how to use CSRF tokens from client code
const ExampleClientHTML = `
<!DOCTYPE html>
<html>
<head>
	<title>Sign Up with CSRF Protection</title>
</head>
<body>
	<h1>Sign Up</h1>
	
	<!-- Form will be populated with CSRF token via JavaScript -->
	<form id="signupForm" method="POST" action="/api/auth/sign-up/email">
		<!-- Hidden CSRF token field -->
		<input type="hidden" id="csrfToken" name="_csrf" value="">
		
		<label>
			Email:
			<input type="email" name="email" required>
		</label>
		<br/>
		
		<label>
			Password:
			<input type="password" name="password" required>
		</label>
		<br/>
		
		<button type="submit">Sign Up</button>
	</form>

	<script>
		// On page load, fetch CSRF token from server
		document.addEventListener('DOMContentLoaded', async () => {
			try {
				// Make a GET request to get a fresh CSRF token
				const response = await fetch('/api/auth/session', {
					credentials: 'include' // Include cookies
				});
				
				// Extract token from response header
				const token = response.headers.get('X-CSRF-Token');
				if (token) {
					// Set token in form
					document.getElementById('csrfToken').value = token;
				}
			} catch (error) {
				console.error('Failed to fetch CSRF token:', error);
			}
		});

		// Alternative: Using JavaScript for dynamic CSRF requests
		document.getElementById('signupForm').addEventListener('submit', async (e) => {
			e.preventDefault();
			
			const formData = new FormData(this);
			const token = formData.get('_csrf');
			
			try {
				const response = await fetch('/api/auth/sign-up/email', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-CSRF-Token': token,
					},
					credentials: 'include', // Send cookies
					body: JSON.stringify({
						email: formData.get('email'),
						password: formData.get('password'),
					})
				});
				
				if (response.ok) {
					alert('Sign up successful!');
					window.location.href = '/dashboard';
				} else {
					const error = await response.json();
					alert('Sign up failed: ' + error.message);
				}
			} catch (error) {
				alert('Error: ' + error.message);
			}
		});
	</script>
</body>
</html>
`

// ExampleAPIClient shows how to use CSRF protection with an HTTP API client
func ExampleAPIClient() {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar, // Enable cookie jar to store CSRF secret
	}

	// 1. Make initial GET request to get CSRF token
	req1, _ := http.NewRequest(http.MethodGet, "http://localhost:3000/api/auth/session", nil)
	resp1, _ := client.Do(req1)
	defer resp1.Body.Close()

	// Extract CSRF token from response header
	csrfToken := resp1.Header.Get("X-CSRF-Token")

	// 2. Make POST request with CSRF token
	req2, _ := http.NewRequest(http.MethodPost, "http://localhost:3000/api/auth/sign-in/email", nil)

	// Include CSRF token in header
	req2.Header.Set("X-CSRF-Token", csrfToken)
	req2.Header.Set("Content-Type", "application/json")

	// Cookies (including CSRF secret) are automatically sent by the client
	resp2, _ := client.Do(req2)
	defer resp2.Body.Close()

	// Check response
	if resp2.StatusCode == http.StatusOK {
		log.Println("Request succeeded with CSRF protection!")
	}
}
