package examples

import (
	"log"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	httpdelivery "github.com/m-t-a97/go-better-auth/internal/delivery/http"
	"github.com/m-t-a97/go-better-auth/internal/domain"
	"github.com/m-t-a97/go-better-auth/internal/usecase"
	"github.com/m-t-a97/go-better-auth/pkg/ratelimit"
)

func main() {
	// Initialize your auth use cases
	// (example assumes you have these set up)
	var authUseCase *usecase.AuthUseCase
	var oauthUseCase *usecase.OAuthUseCase
	var mfaUseCase *usecase.MFAUseCase

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	defer redisClient.Close()

	// Create Redis-based rate limiter
	rateLimiter := ratelimit.NewRedisRateLimiter(redisClient, "auth:")

	// Alternative: Use in-memory rate limiter for development
	// rateLimiter := ratelimit.NewMemoryRateLimiter("auth:")

	// Get default presets
	presets := ratelimit.DefaultPresets()

	// Create rate limiting middlewares for different endpoint groups
	authMiddleware := ratelimit.NewMiddleware(
		rateLimiter,
		domain.StrategyIP,
		presets.Auth,
		15*time.Minute,
	)

	mfaMiddleware := ratelimit.NewMiddleware(
		rateLimiter,
		domain.StrategyIP,
		presets.MFA,
		5*time.Minute,
	)

	emailMiddleware := ratelimit.NewMiddleware(
		rateLimiter,
		domain.StrategyIP,
		presets.Auth,
		15*time.Minute,
	)

	sensitiveMiddleware := ratelimit.NewMiddleware(
		rateLimiter,
		domain.StrategyIP,
		presets.Sensitive,
		30*time.Minute,
	)

	// Create HTTP handler with MFA support
	handler := httpdelivery.NewHandlerWithMFA(authUseCase, oauthUseCase, mfaUseCase)

	// Set the rate limiter
	handler.SetRateLimiter(rateLimiter)

	// Add named middlewares for different endpoint groups
	handler.AddRateLimitMiddleware("auth", authMiddleware)
	handler.AddRateLimitMiddleware("mfa", mfaMiddleware)
	handler.AddRateLimitMiddleware("email", emailMiddleware)
	handler.AddRateLimitMiddleware("sensitive", sensitiveMiddleware)

	// Setup router with rate limiting applied to endpoints
	router := handler.SetupRouter()

	// Start server
	log.Println("Server starting on :3000 with rate limiting enabled")
	if err := http.ListenAndServe(":3000", router); err != nil {
		log.Fatal(err)
	}
}

// ExampleCustomRateLimiting shows how to apply custom rate limits to specific endpoints
func ExampleCustomRateLimiting() {
	// Create Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Create rate limiter
	limiter := ratelimit.NewRedisRateLimiter(redisClient, "api:")

	// Create middleware with 10 requests per minute per IP
	middleware := ratelimit.NewMiddleware(
		limiter,
		domain.StrategyIP,
		10,
		time.Minute,
	)

	// Create endpoint-specific middleware with stricter limit (5 per 5 minutes)
	strictMiddleware := middleware.EndpointMiddleware(5, 5*time.Minute)

	// Use in your router
	mux := http.NewServeMux()
	mux.HandleFunc("/public", middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Public endpoint"))
	})).ServeHTTP)

	mux.HandleFunc("/sensitive", strictMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Sensitive endpoint"))
	})).ServeHTTP)
}

// ExampleStrategyComparison shows the different rate limiting strategies
func ExampleStrategyComparison() {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	limiter := ratelimit.NewRedisRateLimiter(redisClient, "example:")

	// Strategy 1: IP-based (best for public APIs)
	ipLimiter := ratelimit.NewMiddleware(limiter, domain.StrategyIP, 100, time.Hour)

	// Strategy 2: User ID-based (best for authenticated endpoints)
	userLimiter := ratelimit.NewMiddleware(limiter, domain.StrategyUserID, 1000, time.Hour)

	// Strategy 3: API Key-based (best for API client rate limiting)
	keyLimiter := ratelimit.NewMiddleware(limiter, domain.StrategyAPIKey, 5000, time.Hour)

	// Strategy 4: IP + Endpoint (granular control per endpoint)
	endpointLimiter := ratelimit.NewMiddleware(limiter, domain.StrategyIPAndEndpoint, 50, time.Hour)

	_ = ipLimiter
	_ = userLimiter
	_ = keyLimiter
	_ = endpointLimiter
}
