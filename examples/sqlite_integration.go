package examples

import (
	"context"
	"database/sql"
	"log"

	"github.com/m-t-a97/go-better-auth/internal/infrastructure/sqlite"
	"github.com/m-t-a97/go-better-auth/pkg/csrf"
	"github.com/m-t-a97/go-better-auth/pkg/gobetterauth"
)

// SQLiteIntegrationExample demonstrates how to set up go-better-auth with SQLite
func SQLiteIntegrationExample() {
	// Step 1: Create SQLite adapter and initialize database
	db, err := initSQLiteDatabase("./auth_example.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Step 2: Configure authentication with SQLite
	config := &gobetterauth.Config{
		Database: gobetterauth.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: "./auth_example.db",
			DB:               db,
		},
		BaseURL: "http://localhost:3000",
		EmailAndPassword: gobetterauth.EmailPasswordConfig{
			Enabled:                  true,
			RequireEmailVerification: false,
			AutoSignIn:               true,
		},
		Session: gobetterauth.SessionConfig{
			ExpiresIn:        86400, // 24 hours
			UpdateExpiration: true,
		},
		SocialProviders: gobetterauth.SocialProvidersConfig{
			// Configure providers as needed
		},
		Advanced: gobetterauth.AdvancedConfig{
			RateLimiting:   true,
			TrustedOrigins: []string{"http://localhost:3000"},
			SecureCookies:  false, // Set to true in production
		},
	}

	// Step 3: Initialize BetterAuth
	// Note: Currently SQLite is marked as TODO in the New function
	// You can pass a db connection and use the postgres repositories as a workaround
	// This will be fully supported in a future release
	auth, err := gobetterauth.New(config)
	if err != nil {
		log.Fatalf("Failed to initialize BetterAuth: %v", err)
	}

	log.Println("✓ BetterAuth initialized with SQLite successfully!")
	log.Println("✓ Database file created: ./auth_example.db")
	log.Printf("✓ Auth system ready\n")
	_ = auth
}

// initSQLiteDatabase creates a SQLite database and runs migrations
func initSQLiteDatabase(dbPath string) (*sql.DB, error) {
	// Create SQLite adapter
	adapter, err := sqlite.NewSQLiteAdapter(dbPath)
	if err != nil {
		return nil, err
	}

	db := adapter.GetDB()
	ctx := context.Background()

	// Run main migrations
	if _, err := db.ExecContext(ctx, sqlite.SQLiteMigrationSQL); err != nil {
		return nil, err
	}

	// Run MFA migrations
	if _, err := db.ExecContext(ctx, sqlite.SQLiteMFAMigrationSQL); err != nil {
		return nil, err
	}

	// Initialize CSRF schema
	csrfRepo := csrf.NewSQLiteRepository(db)
	if err := csrfRepo.InitSchema(ctx); err != nil {
		return nil, err
	}

	return db, nil
}
