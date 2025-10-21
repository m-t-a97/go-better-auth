package storage

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig holds Redis secondary storage configuration
type RedisConfig struct {
	// Host is the Redis server host (default: "localhost")
	Host string
	// Port is the Redis server port (default: 6379)
	Port int
	// DB is the Redis database number (default: 0)
	DB int
	// Password is the Redis password (optional)
	Password string
	// TLS enables TLS connection to Redis (default: false)
	TLS bool
	// MaxRetries is the maximum number of retries (default: 3)
	MaxRetries int
	// PoolSize is the connection pool size (default: 10)
	PoolSize int
}

// RedisSecondaryStorage implements SecondaryStorage interface using Redis.
// It provides key-value storage with optional TTL for session data and rate limiting.
type RedisSecondaryStorage struct {
	client *redis.Client
	logger *slog.Logger
}

// NewRedisSecondaryStorage creates a new Redis secondary storage instance.
// It establishes a connection to Redis for session caching and rate limiting.
func NewRedisSecondaryStorage(cfg *RedisConfig, existingClient *redis.Client) (*RedisSecondaryStorage, error) {
	// Initialize logger
	logger := slog.Default()

	if cfg == nil && existingClient == nil {
		logger.Error("No redis config provided")
		return nil, fmt.Errorf("no redis config provided")
	}

	// Apply defaults
	cfg = applyDefaults(cfg)

	// Create Redis client
	var client *redis.Client
	if existingClient != nil {
		client = existingClient
	} else {
		client = redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Password:     cfg.Password,
			DB:           cfg.DB,
			MaxRetries:   cfg.MaxRetries,
			PoolSize:     cfg.PoolSize,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		})
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		logger.Error("failed to connect to redis",
			"host", cfg.Host,
			"port", cfg.Port,
			"err", err,
		)
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	logger.Info("successfully connected to redis secondary storage",
		"host", cfg.Host,
		"port", cfg.Port,
		"db", cfg.DB,
	)

	return &RedisSecondaryStorage{
		client: client,
		logger: logger,
	}, nil
}

// applyDefaults applies default configuration values
func applyDefaults(cfg *RedisConfig) *RedisConfig {
	if cfg == nil {
		cfg = &RedisConfig{}
	}
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}
	if cfg.Port == 0 {
		cfg.Port = 6379
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.PoolSize == 0 {
		cfg.PoolSize = 10
	}
	return cfg
}

// Get retrieves the value for the given key from Redis.
func (s *RedisSecondaryStorage) Get(ctx context.Context, key string) (any, error) {
	s.logger.Debug("getting value from redis", "key", key)

	val, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get value from redis: %w", err)
	}

	return val, nil
}

// Set stores the value for the given key in Redis with optional TTL.
// ttlSeconds is the time to live in seconds. If 0 or negative, the key won't expire.
func (s *RedisSecondaryStorage) Set(ctx context.Context, key string, value string, ttlSeconds int) error {
	s.logger.Debug("setting value in redis", "key", key, "ttl_seconds", ttlSeconds)

	var ttl time.Duration
	if ttlSeconds > 0 {
		ttl = time.Duration(ttlSeconds) * time.Second
	}

	if err := s.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set value in redis: %w", err)
	}

	return nil
}

// Delete removes the value for the given key from Redis.
func (s *RedisSecondaryStorage) Delete(ctx context.Context, key string) error {
	s.logger.Debug("deleting value from redis", "key", key)

	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete value from redis: %w", err)
	}

	return nil
}

// Close closes the Redis connection gracefully.
func (s *RedisSecondaryStorage) Close() error {
	s.logger.Info("closing redis connection")
	return s.client.Close()
}
