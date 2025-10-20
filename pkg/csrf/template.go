package csrf

import (
	"html"
)

// HiddenInput generates an HTML hidden input field for CSRF token
// Used in HTML forms to include the CSRF token
func HiddenInput(token string) string {
	return `<input type="hidden" name="` + CSRFFormField + `" value="` + html.EscapeString(token) + `">`
}

// HTMLMetaTag generates an HTML meta tag containing the CSRF token
// Useful for SPAs that fetch the token from the DOM
func HTMLMetaTag(token string) string {
	return `<meta name="csrf-token" content="` + html.EscapeString(token) + `">`
}

// TemplateToken represents a CSRF token for template rendering
type TemplateToken struct {
	Token           string
	FormField       string
	HeaderName      string
	HiddenInputHTML string
	MetaTagHTML     string
}

// NewTemplateToken creates a template-ready CSRF token
func NewTemplateToken(token string) *TemplateToken {
	return &TemplateToken{
		Token:           token,
		FormField:       CSRFFormField,
		HeaderName:      CSRFHeaderName,
		HiddenInputHTML: HiddenInput(token),
		MetaTagHTML:     HTMLMetaTag(token),
	}
}
