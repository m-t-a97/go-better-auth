package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// IsOriginTrusted checks if the given origin is trusted.
// It supports static origins, dynamic origins via callback, and wildcard patterns.
// Returns true if the origin is trusted, false otherwise.
func IsOriginTrusted(origin string, staticOrigins []string, dynamicOrigins func(*http.Request) []string, r *http.Request) bool {
	if origin == "" {
		return false
	}

	// Check static origins (exact match or wildcard)
	for _, trustedOrigin := range staticOrigins {
		if matchesOriginPattern(origin, trustedOrigin) {
			return true
		}
	}

	// Check dynamic origins if provided and request is available
	if dynamicOrigins != nil && r != nil {
		for _, trustedOrigin := range dynamicOrigins(r) {
			if matchesOriginPattern(origin, trustedOrigin) {
				return true
			}
		}
	}

	return false
}

// matchesOriginPattern checks if an origin matches a pattern.
// Supports wildcard patterns like "https://*.example.com"
func matchesOriginPattern(origin, pattern string) bool {
	// Exact match
	if origin == pattern {
		return true
	}

	// Wildcard pattern matching
	if strings.Contains(pattern, "*") {
		return matchesWildcardPattern(origin, pattern)
	}

	return false
}

// matchesWildcardPattern performs wildcard pattern matching for origins.
// Example patterns:
//   - "https://*.example.com" matches "https://app.example.com"
//   - "https://*.example.com" matches "https://api.example.com"
//   - "https://*" matches any HTTPS origin
func matchesWildcardPattern(origin, pattern string) bool {
	// Parse the origin to validate it's a valid URL
	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := originURL.Hostname()
	originScheme := originURL.Scheme
	originPort := originURL.Port()

	// Build the full origin string (scheme://host:port)
	fullOrigin := originScheme + "://" + originHost
	if originPort != "" {
		fullOrigin = originScheme + "://" + originHost + ":" + originPort
	}

	// Check if the full origin matches the pattern
	if matchWildcard(fullOrigin, pattern) {
		return true
	}

	return false
}

// matchWildcard performs simple wildcard matching using * as a wildcard.
// It handles patterns like "https://*.example.com" by splitting and matching segments.
func matchWildcard(text, pattern string) bool {
	// Replace * with a more flexible matching
	parts := strings.Split(pattern, "*")

	if len(parts) == 1 {
		// No wildcard, exact match
		return text == pattern
	}

	// Check if text starts with the first part
	if parts[0] != "" && !strings.HasPrefix(text, parts[0]) {
		return false
	}

	// Remove the matched prefix from text
	text = text[len(parts[0]):]

	// Check all middle parts
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		idx := strings.Index(text, part)
		if idx < 0 {
			return false
		}
		text = text[idx+len(part):]
	}

	// Check if text ends with the last part
	lastPart := parts[len(parts)-1]
	if lastPart != "" && !strings.HasSuffix(text, lastPart) {
		return false
	}

	return true
}

// NormalizeOrigin normalizes an origin URL for comparison.
// It ensures consistent formatting by parsing and reconstructing the URL.
func NormalizeOrigin(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return "", err
	}

	normalized := u.Scheme + "://" + u.Host
	return normalized, nil
}
