package middleware

import (
	"bytes"
	"io"
	"net/http"

	"github.com/m-t-a97/go-better-auth/domain"
)

// HooksMiddleware wraps an http.Handler with before/after hooks from config.
// It provides a centralized way to execute custom logic before and after request processing.
// The middleware:
// - Calls config.Hooks.Before before processing the request with request context
// - Calls config.Hooks.After after processing the request with updated context
// - Returns 403 Forbidden if the Before hook returns an error
// - Silently handles After hook errors to avoid disrupting responses
//
// Hooks receive a RequestContext and can return a HookResponse with modifications.
// The modified context is merged back into the request for processing.
func HooksMiddleware(config *domain.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Parse request context
			ctx := parseRequestContext(r)

			// Before Hook
			if config.Hooks != nil && config.Hooks.Before != nil {
				resp, err := config.Hooks.Before(ctx)
				if err != nil {
					http.Error(w, "request blocked by before hook", http.StatusForbidden)
					return
				}
				// Merge the response back into context if provided
				if resp != nil && resp.Context != nil {
					ctx = mergeContext(ctx, resp.Context)
				}
			}

			// Call the actual handler
			next.ServeHTTP(w, r)

			// After Hook
			if config.Hooks != nil && config.Hooks.After != nil {
				_, _ = config.Hooks.After(ctx)
			}
		})
	}
}

// parseRequestContext extracts request information into a RequestContext
func parseRequestContext(r *http.Request) *domain.RequestContext {
	// Parse query parameters
	queryParams := make(map[string][]string)
	if r.URL.RawQuery != "" {
		queryParams = r.URL.Query()
	}

	// Parse request body if it's a POST/PUT/PATCH request
	var body any
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		bodyBytes, _ := io.ReadAll(r.Body)
		// Re-create the body for downstream handlers
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		if len(bodyBytes) > 0 {
			body = string(bodyBytes)
		}
	}

	return &domain.RequestContext{
		Path:    r.URL.Path,
		Method:  r.Method,
		Body:    body,
		Headers: r.Header,
		Query:   queryParams,
		Request: r,
		Context: make(map[string]any),
	}
}

// mergeContext merges the modified context fields back into the original context
func mergeContext(original, modified *domain.RequestContext) *domain.RequestContext {
	if modified.Path != "" {
		original.Path = modified.Path
	}
	if modified.Method != "" {
		original.Method = modified.Method
	}
	if modified.Body != nil {
		original.Body = modified.Body
	}
	if modified.Headers != nil {
		original.Headers = modified.Headers
	}
	if modified.Query != nil {
		original.Query = modified.Query
	}
	if modified.Context != nil {
		for k, v := range modified.Context {
			original.Context[k] = v
		}
	}
	return original
}
