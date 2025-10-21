package auth

import (
	"net/http"
	"testing"
)

func TestIsOriginTrusted_StaticOrigins(t *testing.T) {
	tests := []struct {
		name          string
		origin        string
		staticOrigins []string
		expected      bool
	}{
		{
			name:          "exact match",
			origin:        "https://example.com",
			staticOrigins: []string{"https://example.com"},
			expected:      true,
		},
		{
			name:          "no match",
			origin:        "https://example.com",
			staticOrigins: []string{"https://other.com"},
			expected:      false,
		},
		{
			name:          "empty origin",
			origin:        "",
			staticOrigins: []string{"https://example.com"},
			expected:      false,
		},
		{
			name:          "multiple origins - first matches",
			origin:        "https://example.com",
			staticOrigins: []string{"https://example.com", "https://other.com"},
			expected:      true,
		},
		{
			name:          "multiple origins - second matches",
			origin:        "https://other.com",
			staticOrigins: []string{"https://example.com", "https://other.com"},
			expected:      true,
		},
		{
			name:          "case sensitive",
			origin:        "https://Example.com",
			staticOrigins: []string{"https://example.com"},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsOriginTrusted(tt.origin, tt.staticOrigins, nil, nil)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsOriginTrusted_DynamicOrigins(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		staticOrigins  []string
		dynamicOrigins func(*http.Request) []string
		request        *http.Request
		expected       bool
	}{
		{
			name:          "dynamic origin matches",
			origin:        "https://dynamic.com",
			staticOrigins: []string{},
			dynamicOrigins: func(r *http.Request) []string {
				return []string{"https://dynamic.com"}
			},
			request:  &http.Request{},
			expected: true,
		},
		{
			name:          "dynamic origin does not match",
			origin:        "https://nope.com",
			staticOrigins: []string{},
			dynamicOrigins: func(r *http.Request) []string {
				return []string{"https://dynamic.com"}
			},
			request:  &http.Request{},
			expected: false,
		},
		{
			name:           "dynamic origins nil, static matches",
			origin:         "https://example.com",
			staticOrigins:  []string{"https://example.com"},
			dynamicOrigins: nil,
			request:        &http.Request{},
			expected:       true,
		},
		{
			name:          "no request, dynamic not checked",
			origin:        "https://dynamic.com",
			staticOrigins: []string{},
			dynamicOrigins: func(r *http.Request) []string {
				return []string{"https://dynamic.com"}
			},
			request:  nil,
			expected: false,
		},
		{
			name:          "both static and dynamic match",
			origin:        "https://example.com",
			staticOrigins: []string{"https://example.com"},
			dynamicOrigins: func(r *http.Request) []string {
				return []string{"https://other.com"}
			},
			request:  &http.Request{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsOriginTrusted(tt.origin, tt.staticOrigins, tt.dynamicOrigins, tt.request)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMatchesOriginPattern_Wildcards(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		pattern  string
		expected bool
	}{
		{
			name:     "exact match",
			origin:   "https://example.com",
			pattern:  "https://example.com",
			expected: true,
		},
		{
			name:     "wildcard subdomain match",
			origin:   "https://app.example.com",
			pattern:  "https://*.example.com",
			expected: true,
		},
		{
			name:     "wildcard subdomain multiple levels matches",
			origin:   "https://api.v1.example.com",
			pattern:  "https://*.example.com",
			expected: true,
		},
		{
			name:     "wildcard scheme",
			origin:   "https://example.com",
			pattern:  "*://example.com",
			expected: true,
		},
		{
			name:     "wildcard full domain",
			origin:   "https://anything.com",
			pattern:  "https://*",
			expected: true,
		},
		{
			name:     "wildcard no match - different host",
			origin:   "https://other.org",
			pattern:  "https://*.example.com",
			expected: false,
		},
		{
			name:     "wildcard with port",
			origin:   "https://app.example.com:3000",
			pattern:  "https://*.example.com:3000",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesOriginPattern(tt.origin, tt.pattern)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMatchWildcardPattern(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		pattern  string
		expected bool
	}{
		{
			name:     "wildcard at end",
			text:     "hello world",
			pattern:  "hello*",
			expected: true,
		},
		{
			name:     "wildcard at start",
			text:     "hello world",
			pattern:  "*world",
			expected: true,
		},
		{
			name:     "wildcard in middle",
			text:     "hello world",
			pattern:  "hello*world",
			expected: true,
		},
		{
			name:     "wildcard only",
			text:     "anything",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "no match",
			text:     "hello",
			pattern:  "bye*",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchWildcard(tt.text, tt.pattern)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestNormalizeOrigin(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		expected  string
		shouldErr bool
	}{
		{
			name:      "valid HTTPS origin",
			origin:    "https://example.com",
			expected:  "https://example.com",
			shouldErr: false,
		},
		{
			name:      "valid HTTP origin",
			origin:    "http://localhost:8080",
			expected:  "http://localhost:8080",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeOrigin(tt.origin)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}
