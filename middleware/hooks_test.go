package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoBetterAuth/go-better-auth/domain"
)

// TestHooksMiddleware_BeforeHookSuccess tests that the before hook is called and request proceeds
func TestHooksMiddleware_BeforeHookSuccess(t *testing.T) {
	beforeCalled := false
	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				beforeCalled = true
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if !beforeCalled {
		t.Error("Before hook was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestHooksMiddleware_BeforeHookError tests that request is blocked when before hook returns error
func TestHooksMiddleware_BeforeHookError(t *testing.T) {
	handlerCalled := false
	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				return nil, errors.New("unauthorized")
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if handlerCalled {
		t.Error("Handler should not be called when before hook returns error")
	}

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

// TestHooksMiddleware_AfterHookSuccess tests that the after hook is called after request processing
func TestHooksMiddleware_AfterHookSuccess(t *testing.T) {
	afterCalled := false
	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			After: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				afterCalled = true
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if !afterCalled {
		t.Error("After hook was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestHooksMiddleware_AfterHookError tests that after hook errors don't disrupt response
func TestHooksMiddleware_AfterHookError(t *testing.T) {
	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			After: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				return nil, errors.New("logging error")
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	// After hook errors should not affect the response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if w.Body.String() != "OK" {
		t.Errorf("Expected response body 'OK', got %s", w.Body.String())
	}
}

// TestHooksMiddleware_BeforeAndAfterHooks tests both hooks are called in correct order
func TestHooksMiddleware_BeforeAndAfterHooks(t *testing.T) {
	callOrder := []string{}

	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				callOrder = append(callOrder, "before")
				return nil, nil
			},
			After: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				callOrder = append(callOrder, "after")
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callOrder = append(callOrder, "handler")
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	expectedOrder := []string{"before", "handler", "after"}
	if len(callOrder) != len(expectedOrder) {
		t.Errorf("Expected %d calls, got %d", len(expectedOrder), len(callOrder))
	}

	for i, expected := range expectedOrder {
		if i >= len(callOrder) {
			t.Errorf("Call order too short")
			break
		}
		if callOrder[i] != expected {
			t.Errorf("Call %d: expected %s, got %s", i, expected, callOrder[i])
		}
	}
}

// TestHooksMiddleware_NoHooks tests that middleware works when no hooks are configured
func TestHooksMiddleware_NoHooks(t *testing.T) {
	config := &domain.Config{
		Hooks: nil,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if w.Body.String() != "OK" {
		t.Errorf("Expected response body 'OK', got %s", w.Body.String())
	}
}

// TestHooksMiddleware_ContextContainsRequestInfo tests that RequestContext has correct information
func TestHooksMiddleware_ContextContainsRequestInfo(t *testing.T) {
	var capturedContext *domain.RequestContext

	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				capturedContext = ctx
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("POST", "/auth/signin", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if capturedContext == nil {
		t.Error("RequestContext was not captured")
		return
	}

	if capturedContext.Path != "/auth/signin" {
		t.Errorf("Expected path '/auth/signin', got %s", capturedContext.Path)
	}

	if capturedContext.Method != "POST" {
		t.Errorf("Expected method 'POST', got %s", capturedContext.Method)
	}

	if capturedContext.Request == nil {
		t.Error("Request should not be nil in RequestContext")
	}
}

// TestHooksMiddleware_MultipleRequests tests that hooks work correctly for multiple requests
func TestHooksMiddleware_MultipleRequests(t *testing.T) {
	callCount := 0

	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				callCount++
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	// Make multiple requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
	}

	if callCount != 3 {
		t.Errorf("Expected 3 hook calls, got %d", callCount)
	}
}

// TestHooksMiddleware_OnlyBeforeHook tests when only before hook is configured
func TestHooksMiddleware_OnlyBeforeHook(t *testing.T) {
	beforeCalled := false

	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				beforeCalled = true
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if !beforeCalled {
		t.Error("Before hook was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestHooksMiddleware_OnlyAfterHook tests when only after hook is configured
func TestHooksMiddleware_OnlyAfterHook(t *testing.T) {
	afterCalled := false

	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			After: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				afterCalled = true
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if !afterCalled {
		t.Error("After hook was not called")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestHooksMiddleware_ModifyingRequestContextProperties tests that users can modify RequestContext by returning HookResponse
func TestHooksMiddleware_ModifyingRequestContextProperties(t *testing.T) {
	var originalContext *domain.RequestContext
	var mergedContext *domain.RequestContext

	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				// Capture the context received by the hook (before modifications)
				originalContext = &domain.RequestContext{
					Path:    ctx.Path,
					Method:  ctx.Method,
					Body:    ctx.Body,
					Headers: ctx.Headers,
					Query:   ctx.Query,
					Request: ctx.Request,
					Context: ctx.Context,
				}
				// Return modified context
				return &domain.HookResponse{
					Context: &domain.RequestContext{
						Path:   "/modified/path",
						Method: "CUSTOM",
						Context: map[string]any{
							"modified": true,
						},
					},
				}, nil
			},
			After: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				// Capture context after hook processing (with merged modifications)
				mergedContext = &domain.RequestContext{
					Path:    ctx.Path,
					Method:  ctx.Method,
					Body:    ctx.Body,
					Headers: ctx.Headers,
					Query:   ctx.Query,
					Request: ctx.Request,
					Context: ctx.Context,
				}
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/original/path", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if originalContext == nil {
		t.Error("Original context was not captured")
		return
	}

	// Verify hook receives the original, unmodified context
	if originalContext.Path != "/original/path" {
		t.Errorf("Expected original path '/original/path', got %s", originalContext.Path)
	}

	if originalContext.Method != "GET" {
		t.Errorf("Expected original method 'GET', got %s", originalContext.Method)
	}

	if mergedContext == nil {
		t.Error("Merged context was not captured")
		return
	}

	// Verify context is merged after the hook
	if mergedContext.Path != "/modified/path" {
		t.Errorf("Expected merged path '/modified/path', got %s", mergedContext.Path)
	}

	if mergedContext.Method != "CUSTOM" {
		t.Errorf("Expected merged method 'CUSTOM', got %s", mergedContext.Method)
	}

	if mergedContext.Context == nil {
		t.Error("Context map should not be nil")
	} else if modified, ok := mergedContext.Context["modified"].(bool); !ok || !modified {
		t.Errorf("Expected Context['modified'] to be true, got %v", mergedContext.Context["modified"])
	}
}

// TestHooksMiddleware_ModifyContextWithHeaders tests that users can modify headers in context
func TestHooksMiddleware_ModifyContextWithHeaders(t *testing.T) {
	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				// Return modified context with headers
				return &domain.HookResponse{
					Context: &domain.RequestContext{
						Headers: map[string][]string{
							"X-Custom-Header": {"custom-value"},
						},
					},
				}, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestHooksMiddleware_AccessContextProperties tests that hooks can access all context properties
func TestHooksMiddleware_AccessContextProperties(t *testing.T) {
	var capturedContext *domain.RequestContext

	config := &domain.Config{
		Hooks: &domain.HooksConfig{
			Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
				capturedContext = ctx
				return nil, nil
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := HooksMiddleware(config)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/auth/test?email=test@example.com", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if capturedContext == nil {
		t.Error("RequestContext was not captured")
		return
	}

	// Verify all properties are present
	if capturedContext.Path != "/auth/test" {
		t.Errorf("Expected path '/auth/test', got %s", capturedContext.Path)
	}

	if capturedContext.Method != "GET" {
		t.Errorf("Expected method 'GET', got %s", capturedContext.Method)
	}

	if capturedContext.Headers == nil {
		t.Error("Headers should not be nil")
	}

	if capturedContext.Query == nil {
		t.Error("Query parameters should not be nil")
	}

	if len(capturedContext.Query["email"]) == 0 {
		t.Error("Query parameter 'email' should be present")
	}

	if capturedContext.Context == nil {
		t.Error("Context map should not be nil")
	}

	if capturedContext.Request == nil {
		t.Error("Request object should not be nil")
	}
}
