package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/stretchr/testify/assert"
)

func TestCORSMiddleware_TrustedOrigin(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	middleware := NewCORSMiddleware(trustedOrigins)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
}

func TestCORSMiddleware_UntrustedOrigin(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	middleware := NewCORSMiddleware(trustedOrigins)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://other.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_Preflight(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	middleware := NewCORSMiddleware(trustedOrigins)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("OPTIONS", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_WildcardOrigin(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://*.example.com"},
	}

	middleware := NewCORSMiddleware(trustedOrigins)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://api.example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://api.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_DynamicOrigin(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		DynamicOrigins: func(r *http.Request) []string {
			// Allow origins based on a custom header
			if val := r.Header.Get("X-Custom-Origin"); val != "" {
				return []string{val}
			}
			return []string{}
		},
	}

	middleware := NewCORSMiddleware(trustedOrigins)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://dynamic.com")
	req.Header.Set("X-Custom-Origin", "https://dynamic.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://dynamic.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_CustomAllowedMethods(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	middleware := NewCORSMiddleware(trustedOrigins).
		WithAllowedMethods([]string{"GET", "POST"})

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	allowedMethods := w.Header().Get("Access-Control-Allow-Methods")
	assert.Contains(t, allowedMethods, "GET")
	assert.Contains(t, allowedMethods, "POST")
	assert.NotContains(t, allowedMethods, "DELETE")
}

func TestCORSMiddleware_CustomAllowedHeaders(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	customHeaders := []string{"X-Custom-Header", "X-API-Key"}
	middleware := NewCORSMiddleware(trustedOrigins).
		WithAllowedHeaders(customHeaders)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	allowedHeaders := w.Header().Get("Access-Control-Allow-Headers")
	for _, header := range customHeaders {
		assert.Contains(t, allowedHeaders, header)
	}
}

func TestCORSMiddleware_ExposedHeaders(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	exposedHeaders := []string{"X-Total-Count", "X-Page"}
	middleware := NewCORSMiddleware(trustedOrigins).
		WithExposedHeaders(exposedHeaders)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	exposedHeadersValue := w.Header().Get("Access-Control-Expose-Headers")
	for _, header := range exposedHeaders {
		assert.Contains(t, exposedHeadersValue, header)
	}
}

func TestCORSMiddleware_NoCredentials(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	middleware := NewCORSMiddleware(trustedOrigins).
		WithCredentials(false)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORSMiddleware_CustomMaxAge(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	middleware := NewCORSMiddleware(trustedOrigins).
		WithMaxAge(7200)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "http://localhost:8080", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "7200", w.Header().Get("Access-Control-Max-Age"))
}

func TestCORSMiddleware_NoOriginHeader(t *testing.T) {
	trustedOrigins := &domain.TrustedOriginsConfig{
		StaticOrigins: []string{"https://example.com"},
	}

	middleware := NewCORSMiddleware(trustedOrigins)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "http://localhost:8080", nil)
	// No Origin header

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestIntToString(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{123, "123"},
		{9999, "9999"},
		{-1, "0"},
	}

	for _, tt := range tests {
		result := intToString(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}
