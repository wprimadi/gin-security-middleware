package middleware

import (
	"bytes"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

// SecurityConfig configuration for security middleware
type SecurityConfig struct {
	MaxLength             int
	BlockSQLInjection     bool
	BlockXSS              bool
	BlockPathTraversal    bool
	BlockCommandInjection bool
	SanitizeInput         bool
	CustomPatterns        []string
	WhitelistedFields     []string

	// Enhanced options
	ValidateHeaders   bool     // Validate HTTP headers
	ValidateCookies   bool     // Validate cookies
	ValidateJSONBody  bool     // Validate JSON body
	HeadersToValidate []string // Specific headers to validate
	SkipUserAgent     bool     // Skip User-Agent validation

	// Security headers options
	EnableSecurityHeaders bool   // Enable automatic security headers
	CSPPolicy             string // Content-Security-Policy
	FrameOptions          string // X-Frame-Options (DENY, SAMEORIGIN)
	ContentTypeNosniff    bool   // X-Content-Type-Options: nosniff
	XSSProtection         string // X-XSS-Protection
	StrictTransportSec    string // Strict-Transport-Security (HSTS)
	ReferrerPolicy        string // Referrer-Policy
	PermissionsPolicy     string // Permissions-Policy
}

// DefaultSecurityConfig returns default configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		MaxLength:             10000,
		BlockSQLInjection:     true,
		BlockXSS:              true,
		BlockPathTraversal:    true,
		BlockCommandInjection: true,
		SanitizeInput:         true,
		WhitelistedFields:     []string{},

		// Enhanced defaults
		ValidateHeaders:   true,
		ValidateCookies:   true,
		ValidateJSONBody:  true,
		HeadersToValidate: []string{"X-Forwarded-For", "X-Real-IP", "X-User-Id", "X-API-Key"},
		SkipUserAgent:     true, // User-Agent often has special chars

		// Security headers defaults
		EnableSecurityHeaders: true,
		CSPPolicy:             "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
		FrameOptions:          "DENY",
		ContentTypeNosniff:    true,
		XSSProtection:         "1; mode=block",
		StrictTransportSec:    "max-age=31536000; includeSubDomains",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		PermissionsPolicy:     "geolocation=(), microphone=(), camera=()",
	}
}

// EnhancedSecurityMiddleware - Full coverage middleware
func EnhancedSecurityMiddleware(config SecurityConfig) gin.HandlerFunc {
	validator := NewSecurityValidator(config)

	return func(c *gin.Context) {
		// Apply security headers first
		if config.EnableSecurityHeaders {
			applySecurityHeaders(c, config)
		}

		// 1. Validate Query Parameters
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				if err := validator.ValidateInput(key, value); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error":  "Invalid input detected in query parameters",
						"field":  key,
						"reason": err.(*SecurityError).Type,
					})
					c.Abort()
					return
				}
			}
		}

		// 2. Validate Headers
		if config.ValidateHeaders {
			for _, headerName := range config.HeadersToValidate {
				if headerValue := c.GetHeader(headerName); headerValue != "" {
					if err := validator.ValidateInput(headerName, headerValue); err != nil {
						c.JSON(http.StatusBadRequest, gin.H{
							"error":  "Invalid input detected in headers",
							"field":  headerName,
							"reason": err.(*SecurityError).Type,
						})
						c.Abort()
						return
					}
				}
			}

			// Validate User-Agent if not skipped
			if !config.SkipUserAgent {
				if ua := c.GetHeader("User-Agent"); ua != "" {
					if err := validator.ValidateInput("User-Agent", ua); err != nil {
						c.JSON(http.StatusBadRequest, gin.H{
							"error":  "Invalid User-Agent",
							"reason": err.(*SecurityError).Type,
						})
						c.Abort()
						return
					}
				}
			}
		}

		// 3. Validate Cookies
		if config.ValidateCookies {
			for _, cookie := range c.Request.Cookies() {
				if err := validator.ValidateInput(cookie.Name, cookie.Value); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error":  "Invalid input detected in cookies",
						"field":  cookie.Name,
						"reason": err.(*SecurityError).Type,
					})
					c.Abort()
					return
				}
			}
		}

		// 4. Validate Form Data
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.ContentType()

			// Handle JSON Body
			if config.ValidateJSONBody && strings.Contains(contentType, "application/json") {
				// Read body
				bodyBytes, err := io.ReadAll(c.Request.Body)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
					c.Abort()
					return
				}

				// Restore body for later use
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

				// Validate JSON content
				var jsonData interface{}
				if err := json.Unmarshal(bodyBytes, &jsonData); err == nil {
					if err := validator.ValidateJSON(jsonData); err != nil {
						c.JSON(http.StatusBadRequest, gin.H{
							"error":  "Invalid input detected in JSON body",
							"reason": err.(*SecurityError).Type,
						})
						c.Abort()
						return
					}
				}

				// Restore body again for handler
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			// Handle Form Data
			if strings.Contains(contentType, "application/x-www-form-urlencoded") ||
				strings.Contains(contentType, "multipart/form-data") {

				if err := c.Request.ParseForm(); err == nil {
					for key, values := range c.Request.PostForm {
						for _, value := range values {
							if err := validator.ValidateInput(key, value); err != nil {
								c.JSON(http.StatusBadRequest, gin.H{
									"error":  "Invalid input detected in form data",
									"field":  key,
									"reason": err.(*SecurityError).Type,
								})
								c.Abort()
								return
							}
						}
					}
				}
			}
		}

		c.Next()
	}
}

// SecurityValidator validator for input security
type SecurityValidator struct {
	config SecurityConfig

	sqlPatterns     []*regexp.Regexp
	xssPatterns     []*regexp.Regexp
	pathPatterns    []*regexp.Regexp
	commandPatterns []*regexp.Regexp
	customPatterns  []*regexp.Regexp
}

// NewSecurityValidator creates a new validator
func NewSecurityValidator(config SecurityConfig) *SecurityValidator {
	v := &SecurityValidator{
		config: config,
	}

	// Compile SQL Injection patterns
	if config.BlockSQLInjection {
		sqlPatternStrings := []string{
			`(?i)(union\s+select)`,
			`(?i)(select\s+.*\s+from)`,
			`(?i)(insert\s+into)`,
			`(?i)(delete\s+from)`,
			`(?i)(drop\s+table)`,
			`(?i)(update\s+.*\s+set)`,
			`(?i)(exec\s*\()`,
			`(?i)(execute\s*\()`,
			`(?i)(or\s+1\s*=\s*1)`,
			`(?i)(and\s+1\s*=\s*1)`,
			`(?i)('|\"|;|--|#|\/\*|\*\/|xp_)`,
			`(?i)(char\s*\()`,
			`(?i)(concat\s*\()`,
			`(?i)(0x[0-9a-f]+)`, // Hex encoding
			`(?i)(waitfor\s+delay)`,
			`(?i)(benchmark\s*\()`,
		}
		for _, pattern := range sqlPatternStrings {
			v.sqlPatterns = append(v.sqlPatterns, regexp.MustCompile(pattern))
		}
	}

	// Compile XSS patterns
	if config.BlockXSS {
		xssPatternStrings := []string{
			`(?i)<script[^>]*>.*?</script>`,
			`(?i)<iframe[^>]*>.*?</iframe>`,
			`(?i)<object[^>]*>.*?</object>`,
			`(?i)<embed[^>]*>`,
			`(?i)<applet[^>]*>.*?</applet>`,
			`(?i)on\w+\s*=`,
			`(?i)javascript\s*:`,
			`(?i)<img[^>]+src[^>]*>`,
			`(?i)<svg[^>]*>.*?</svg>`,
			`(?i)<link[^>]*>`,
			`(?i)<meta[^>]*>`,
			`(?i)<style[^>]*>.*?</style>`,
			`(?i)expression\s*\(`,
			`(?i)@import`,
			`(?i)vbscript\s*:`,
			`(?i)data:text/html`,
			`(?i)<base[^>]*>`,
		}
		for _, pattern := range xssPatternStrings {
			v.xssPatterns = append(v.xssPatterns, regexp.MustCompile(pattern))
		}
	}

	// Compile Path Traversal patterns
	if config.BlockPathTraversal {
		pathPatternStrings := []string{
			`\.\.\/`,
			`\.\.\\`,
			`%2e%2e%2f`,
			`%2e%2e\/`,
			`%2e%2e%5c`,
			`\.\.%2f`,
			`\.\.%5c`,
			`%252e%252e%252f`, // Double encoded
		}
		for _, pattern := range pathPatternStrings {
			v.pathPatterns = append(v.pathPatterns, regexp.MustCompile(pattern))
		}
	}

	// Compile Command Injection patterns
	if config.BlockCommandInjection {
		commandPatternStrings := []string{
			`(?i)(;\s*\w+)`,
			`(?i)(\|\s*\w+)`,
			`(?i)(&&\s*\w+)`,
			`(?i)(\$\(.*\))`,
			`(?i)(>\s*/\w+)`,
			`(?i)(<\s*/\w+)`,
			"(?i)(`.*`)",
			`(?i)(\|\|)`,
			`(?i)(&[^&])`,
		}
		for _, pattern := range commandPatternStrings {
			v.commandPatterns = append(v.commandPatterns, regexp.MustCompile(pattern))
		}
	}

	// Compile custom patterns
	for _, pattern := range config.CustomPatterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			v.customPatterns = append(v.customPatterns, compiled)
		}
	}

	return v
}

// ValidateInput validates string input
func (v *SecurityValidator) ValidateInput(fieldName, input string) error {
	// Check whitelist
	for _, whitelisted := range v.config.WhitelistedFields {
		if fieldName == whitelisted {
			return nil
		}
	}

	// Check max length
	if v.config.MaxLength > 0 && utf8.RuneCountInString(input) > v.config.MaxLength {
		return &SecurityError{
			Type:  "length_exceeded",
			Field: fieldName,
			Value: input,
		}
	}

	// Check SQL Injection
	if v.config.BlockSQLInjection {
		for _, pattern := range v.sqlPatterns {
			if pattern.MatchString(input) {
				return &SecurityError{
					Type:  "sql_injection",
					Field: fieldName,
					Value: input,
				}
			}
		}
	}

	// Check XSS
	if v.config.BlockXSS {
		for _, pattern := range v.xssPatterns {
			if pattern.MatchString(input) {
				return &SecurityError{
					Type:  "xss",
					Field: fieldName,
					Value: input,
				}
			}
		}
	}

	// Check Path Traversal
	if v.config.BlockPathTraversal {
		for _, pattern := range v.pathPatterns {
			if pattern.MatchString(input) {
				return &SecurityError{
					Type:  "path_traversal",
					Field: fieldName,
					Value: input,
				}
			}
		}
	}

	// Check Command Injection
	if v.config.BlockCommandInjection {
		for _, pattern := range v.commandPatterns {
			if pattern.MatchString(input) {
				return &SecurityError{
					Type:  "command_injection",
					Field: fieldName,
					Value: input,
				}
			}
		}
	}

	// Check custom patterns
	for _, pattern := range v.customPatterns {
		if pattern.MatchString(input) {
			return &SecurityError{
				Type:  "custom_pattern",
				Field: fieldName,
				Value: input,
			}
		}
	}

	return nil
}

// ValidateJSON validates JSON data recursively
func (v *SecurityValidator) ValidateJSON(data interface{}) error {
	switch value := data.(type) {
	case map[string]interface{}:
		for key, val := range value {
			// Validate key
			if err := v.ValidateInput(key, key); err != nil {
				return err
			}
			// Validate value recursively
			if err := v.ValidateJSON(val); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, item := range value {
			if err := v.ValidateJSON(item); err != nil {
				return err
			}
		}
	case string:
		if err := v.ValidateInput("json_value", value); err != nil {
			return err
		}
	}
	return nil
}

// SanitizeString cleans dangerous characters from string
func (v *SecurityValidator) SanitizeString(input string) string {
	if !v.config.SanitizeInput {
		return input
	}

	// HTML escape
	sanitized := html.EscapeString(input)

	// Remove null bytes
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")

	// Normalize whitespace
	sanitized = strings.TrimSpace(sanitized)

	return sanitized
}

// applySecurityHeaders sets security headers on response
func applySecurityHeaders(c *gin.Context, config SecurityConfig) {
	// Content Security Policy
	if config.CSPPolicy != "" {
		c.Header("Content-Security-Policy", config.CSPPolicy)
	}

	// X-Frame-Options
	if config.FrameOptions != "" {
		c.Header("X-Frame-Options", config.FrameOptions)
	}

	// X-Content-Type-Options
	if config.ContentTypeNosniff {
		c.Header("X-Content-Type-Options", "nosniff")
	}

	// X-XSS-Protection
	if config.XSSProtection != "" {
		c.Header("X-XSS-Protection", config.XSSProtection)
	}

	// Strict-Transport-Security (HSTS)
	if config.StrictTransportSec != "" {
		c.Header("Strict-Transport-Security", config.StrictTransportSec)
	}

	// Referrer-Policy
	if config.ReferrerPolicy != "" {
		c.Header("Referrer-Policy", config.ReferrerPolicy)
	}

	// Permissions-Policy
	if config.PermissionsPolicy != "" {
		c.Header("Permissions-Policy", config.PermissionsPolicy)
	}

	// Additional security headers
	c.Header("X-Permitted-Cross-Domain-Policies", "none")
	c.Header("X-Download-Options", "noopen")
}

// SecurityError custom error for security issues
type SecurityError struct {
	Type  string
	Field string
	Value string
}

func (e *SecurityError) Error() string {
	return "Security violation detected: " + e.Type + " in field: " + e.Field
}

// Example usage:
//
// func main() {
//     r := gin.Default()
//
//     // Use enhanced middleware with full coverage
//     config := DefaultSecurityConfig()
//     config.HeadersToValidate = []string{"X-User-Id", "X-API-Key", "X-Forwarded-For"}
//
//     // Customize security headers
//     config.CSPPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'"
//     config.FrameOptions = "SAMEORIGIN"
//
//     r.Use(EnhancedSecurityMiddleware(config))
//
//     r.POST("/api/users", func(c *gin.Context) {
//         // All inputs (query, form, JSON, headers, cookies) are validated
//         // Security headers are automatically set on response
//         var user User
//         c.ShouldBindJSON(&user)
//         c.JSON(200, gin.H{"message": "User created safely"})
//     })
//
//     r.Run(":8080")
// }

// SecureHeadersMiddleware - Standalone middleware for security headers only
func SecureHeadersMiddleware(config SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		applySecurityHeaders(c, config)
		c.Next()
	}
}

// StrictSecurityConfig returns a strict security configuration
func StrictSecurityConfig() SecurityConfig {
	config := DefaultSecurityConfig()

	// Stricter CSP
	config.CSPPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"

	// Stricter HSTS
	config.StrictTransportSec = "max-age=63072000; includeSubDomains; preload"

	// Stricter Referrer Policy
	config.ReferrerPolicy = "no-referrer"

	// Stricter Permissions Policy
	config.PermissionsPolicy = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"

	return config
}
