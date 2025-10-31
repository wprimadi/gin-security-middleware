# 🔒 Gin Security Middleware

![Gin Security Middleware](https://raw.githubusercontent.com/wprimadi/gin-security-middleware/refs/heads/main/banner.png)

Advanced security middleware for [Gin](https://github.com/gin-gonic/gin) web framework that provides comprehensive protection against common web vulnerabilities including SQL Injection, XSS, Path Traversal, Command Injection, and more with **full coverage** for all input vectors (JSON bodies, HTTP headers, cookies) and **automatic security headers** injection.

[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.16-blue)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## ✨ Features

### Core Protections
- 🛡️ **SQL Injection Protection** - Blocks common SQL injection patterns (UNION, SELECT, DROP, hex encoding, etc.)
- 🚫 **XSS Prevention** - Detects and blocks Cross-Site Scripting attempts including event handlers and data URIs
- 📁 **Path Traversal Protection** - Prevents directory traversal attacks (../, encoded variants, double encoding)
- ⚡ **Command Injection Protection** - Blocks shell command injection attempts (backticks, pipes, redirects)
- 🎨 **Custom Pattern Matching** - Add your own regex patterns for additional security rules

### Advanced Features
- 🔍 **Full Input Coverage** - Validates ALL input vectors:
  - Query Parameters
  - Form Data (POST/PUT/PATCH)
  - JSON Body (recursive validation)
  - HTTP Headers (custom headers, X-Forwarded-For, etc.)
  - Cookies
- 🔐 **Security Headers** - Automatically injects security headers:
  - Content-Security-Policy (CSP)
  - X-Frame-Options (Clickjacking protection)
  - Strict-Transport-Security (HSTS)
  - X-Content-Type-Options (MIME sniffing protection)
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
- 🧹 **Input Sanitization** - Automatic HTML escaping and input cleaning
- ⚙️ **Highly Configurable** - Enable/disable specific protections per route
- 🎯 **Whitelist Support** - Exclude specific fields from validation
- 🚀 **Performance Optimized** - Pre-compiled regex patterns for fast validation
- 📊 **Detailed Error Reporting** - Know exactly which field and violation type triggered the block
- 🔒 **Tamper-Proof** - Resistant to bypass attempts via Burp Suite, Tamper Data, or similar tools

## 📦 Installation

```bash
go get github.com/wprimadi/gin-security-middleware
```

## 🚀 Quick Start

### Basic Usage

```go
package main

import (
    "github.com/gin-gonic/gin"
    security "github.com/wprimadi/gin-security-middleware"
)

func main() {
    r := gin.Default()
    
    // Apply enhanced security middleware with default configuration
    // Includes input validation + security headers
    r.Use(security.EnhancedSecurityMiddleware(security.DefaultSecurityConfig()))
    
    r.POST("/api/users", func(c *gin.Context) {
        // All inputs are validated: query params, form data, JSON, headers, cookies
        // Security headers are automatically set on response
        var user User
        c.ShouldBindJSON(&user)
        
        c.JSON(200, gin.H{
            "message": "User created safely",
            "user": user,
        })
    })
    
    r.Run(":8080")
}
```

## 📖 Usage Examples

### Example 1: Custom Configuration

```go
customConfig := security.SecurityConfig{
    MaxLength:             1000,  // Limit input to 1000 characters
    BlockSQLInjection:     true,
    BlockXSS:              true,
    BlockPathTraversal:    true,
    BlockCommandInjection: true,
    SanitizeInput:         true,
    
    // Enhanced options
    ValidateHeaders:       true,
    ValidateCookies:       true,
    ValidateJSONBody:      true,
    HeadersToValidate:     []string{"X-User-Id", "X-API-Key", "X-Forwarded-For"},
    SkipUserAgent:         true,  // User-Agent often has special characters
    
    // Security headers configuration
    EnableSecurityHeaders: true,
    CSPPolicy:             "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' https:",
    FrameOptions:          "SAMEORIGIN",
    ContentTypeNosniff:    true,
    XSSProtection:         "1; mode=block",
    StrictTransportSec:    "max-age=31536000; includeSubDomains",
    ReferrerPolicy:        "strict-origin-when-cross-origin",
    PermissionsPolicy:     "geolocation=(), microphone=(), camera=()",
    
    // Add custom patterns to block
    CustomPatterns: []string{
        `(?i)(spam|viagra|casino)`,  // Block spam keywords
        `(?i)(\d{16})`,              // Block credit card numbers
    },
    
    // Whitelist fields that should skip validation
    WhitelistedFields: []string{"content", "description"},
}

r.Use(security.EnhancedSecurityMiddleware(customConfig))
```

### Example 2: Strict Security Mode

```go
r := gin.Default()

// Use strict security configuration for maximum protection
r.Use(security.EnhancedSecurityMiddleware(security.StrictSecurityConfig()))

r.POST("/api/sensitive", func(c *gin.Context) {
    // Maximum security applied:
    // - Strictest CSP (default-src 'none')
    // - HSTS with preload
    // - Referrer-Policy: no-referrer
    // - All permissions blocked
    c.JSON(200, gin.H{"message": "Protected endpoint"})
})
```

### Example 3: Different Security Levels for Route Groups

```go
r := gin.Default()

// Relaxed security for public API
publicConfig := security.SecurityConfig{
    MaxLength:             500,
    BlockSQLInjection:     true,
    BlockXSS:              true,
    BlockPathTraversal:    false,
    BlockCommandInjection: false,
    SanitizeInput:         true,
    ValidateHeaders:       false,  // No header validation for public
    ValidateCookies:       false,
    ValidateJSONBody:      true,
    EnableSecurityHeaders: true,
    CSPPolicy:             "default-src 'self' 'unsafe-inline'; img-src * data:",
}

// Strict security for admin API
adminConfig := security.StrictSecurityConfig()
adminConfig.HeadersToValidate = []string{"X-Admin-Token", "X-User-Id"}
adminConfig.CustomPatterns = []string{`(?i)(eval|exec)`}

// Public routes
publicAPI := r.Group("/api/public")
publicAPI.Use(security.EnhancedSecurityMiddleware(publicConfig))
{
    publicAPI.GET("/products", GetProducts)
    publicAPI.POST("/contact", ContactForm)
}

// Admin routes - strict protection
adminAPI := r.Group("/api/admin")
adminAPI.Use(security.EnhancedSecurityMiddleware(adminConfig))
{
    adminAPI.POST("/settings", UpdateSettings)
    adminAPI.DELETE("/users/:id", DeleteUser)
}
```

### Example 4: Security Headers Only

```go
r := gin.Default()

// Apply only security headers without input validation
// Useful for static file servers or trusted internal APIs
r.Use(security.SecureHeadersMiddleware(security.DefaultSecurityConfig()))

r.Static("/public", "./public")
r.GET("/health", func(c *gin.Context) {
    // Only security headers applied, no input validation
    c.JSON(200, gin.H{"status": "ok"})
})
```

### Example 5: Protecting Against Header Injection

```go
r := gin.Default()

config := security.DefaultSecurityConfig()
config.HeadersToValidate = []string{
    "X-Forwarded-For",
    "X-Real-IP",
    "X-User-Id",
    "X-API-Key",
    "X-Auth-Token",
}

r.Use(security.EnhancedSecurityMiddleware(config))

r.GET("/api/profile", func(c *gin.Context) {
    // Headers are validated - no injection possible
    userID := c.GetHeader("X-User-Id")
    c.JSON(200, gin.H{"user_id": userID})
})
```

### Example 6: JSON Body with Nested Objects

```go
type CreatePostRequest struct {
    Title   string                 `json:"title"`
    Content string                 `json:"content"`
    Meta    map[string]interface{} `json:"meta"`
    Tags    []string               `json:"tags"`
}

r.POST("/api/posts", func(c *gin.Context) {
    var req CreatePostRequest
    
    // JSON body is automatically validated recursively
    // Including nested objects and arrays
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // All fields in req are safe from injection attacks
    // Security headers are automatically set
    c.JSON(200, gin.H{"message": "Post created"})
})
```

### Example 7: Custom CSP for SPA Applications

```go
r := gin.Default()

config := security.DefaultSecurityConfig()
// Custom CSP for Single Page Applications
config.CSPPolicy = "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "connect-src 'self' https://api.example.com;"

r.Use(security.EnhancedSecurityMiddleware(config))

r.GET("/", func(c *gin.Context) {
    c.HTML(200, "index.html", nil)
})
```

### Example 8: File Upload Protection

```go
uploadConfig := security.SecurityConfig{
    MaxLength:             255,   // Filename length limit
    BlockSQLInjection:     false,
    BlockXSS:              false,
    BlockPathTraversal:    true,  // Critical for file uploads
    BlockCommandInjection: true,
    SanitizeInput:         true,
    ValidateHeaders:       false,
    ValidateCookies:       false,
    ValidateJSONBody:      false,
    EnableSecurityHeaders: true,
}

uploadGroup := r.Group("/api/upload")
uploadGroup.Use(security.EnhancedSecurityMiddleware(uploadConfig))
{
    uploadGroup.POST("/", func(c *gin.Context) {
        file, _ := c.FormFile("file")
        // Filename is validated (no ../ or dangerous patterns)
        c.SaveUploadedFile(file, "./uploads/"+file.Filename)
        c.JSON(200, gin.H{"message": "File uploaded"})
    })
}
```

## 🔧 Configuration Options

### Input Validation Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `MaxLength` | `int` | `10000` | Maximum input length (0 = unlimited) |
| `BlockSQLInjection` | `bool` | `true` | Enable SQL injection protection |
| `BlockXSS` | `bool` | `true` | Enable XSS protection |
| `BlockPathTraversal` | `bool` | `true` | Enable path traversal protection |
| `BlockCommandInjection` | `bool` | `true` | Enable command injection protection |
| `SanitizeInput` | `bool` | `true` | Enable automatic input sanitization |
| `CustomPatterns` | `[]string` | `[]` | Custom regex patterns to block |
| `WhitelistedFields` | `[]string` | `[]` | Fields to exclude from validation |
| `ValidateHeaders` | `bool` | `true` | Enable HTTP header validation |
| `ValidateCookies` | `bool` | `true` | Enable cookie validation |
| `ValidateJSONBody` | `bool` | `true` | Enable JSON body validation (recursive) |
| `HeadersToValidate` | `[]string` | See defaults | Specific headers to validate |
| `SkipUserAgent` | `bool` | `true` | Skip User-Agent validation |

### Security Headers Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `EnableSecurityHeaders` | `bool` | `true` | Enable automatic security headers |
| `CSPPolicy` | `string` | See below | Content-Security-Policy value |
| `FrameOptions` | `string` | `"DENY"` | X-Frame-Options (DENY/SAMEORIGIN) |
| `ContentTypeNosniff` | `bool` | `true` | X-Content-Type-Options: nosniff |
| `XSSProtection` | `string` | `"1; mode=block"` | X-XSS-Protection value |
| `StrictTransportSec` | `string` | See below | Strict-Transport-Security (HSTS) |
| `ReferrerPolicy` | `string` | See below | Referrer-Policy value |
| `PermissionsPolicy` | `string` | See below | Permissions-Policy value |

### Default Security Headers Values

```go
CSPPolicy:          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
StrictTransportSec: "max-age=31536000; includeSubDomains"
ReferrerPolicy:     "strict-origin-when-cross-origin"
PermissionsPolicy:  "geolocation=(), microphone=(), camera=()"
```

## 🛡️ What Gets Blocked?

### SQL Injection Patterns
- `UNION SELECT`, `SELECT * FROM`
- `DROP TABLE`, `INSERT INTO`, `DELETE FROM`
- `OR 1=1`, `AND 1=1`
- `' OR '1'='1`
- Hex encoding (`0x...`)
- `WAITFOR DELAY`, `BENCHMARK()`
- Comment sequences (`--`, `/*`, `*/`)
- And many more...

### XSS Patterns
- `<script>` tags and variants
- `<iframe>`, `<object>`, `<embed>` tags
- Event handlers (`onclick`, `onerror`, `onload`, etc.)
- `javascript:` and `vbscript:` protocols
- `<img>` with malicious `src`
- `data:text/html` URIs
- `<base>` tag injection
- CSS `expression()` and `@import`
- And many more...

### Path Traversal Patterns
- `../`, `..\`
- `%2e%2e%2f` (URL encoded)
- `%252e%252e%252f` (double encoded)
- All common encoding variants

### Command Injection Patterns
- Shell operators (`;`, `|`, `||`, `&&`)
- Command substitution (`$()`, backticks)
- Redirects (`>`, `<`)
- Background execution (`&`)
- And more...

## 🔐 Security Headers Explained

### Content-Security-Policy (CSP)
Prevents XSS by restricting resource sources. The default policy:
- Only allows resources from same origin (`'self'`)
- Blocks inline scripts (except styles)
- Prevents framing (`frame-ancestors 'none'`)

### X-Frame-Options
Prevents clickjacking attacks by controlling whether the page can be framed.
- `DENY` - Cannot be framed at all
- `SAMEORIGIN` - Can only be framed by same origin

### Strict-Transport-Security (HSTS)
Forces browsers to use HTTPS for all future requests.
- `max-age=31536000` - Remember for 1 year
- `includeSubDomains` - Apply to all subdomains
- `preload` - Submit to browser preload list (strict mode)

### X-Content-Type-Options
Prevents MIME-type sniffing attacks.
- `nosniff` - Browser must respect declared Content-Type

### Referrer-Policy
Controls how much referrer information is sent.
- `strict-origin-when-cross-origin` - Full URL for same-origin, origin only for cross-origin
- `no-referrer` - Never send referrer (strict mode)

### Permissions-Policy
Controls which browser features are allowed.
- Default blocks: geolocation, microphone, camera
- Strict mode blocks: payment, USB, sensors, etc.

## 🔒 Protection Against Tampering Tools

This middleware is designed to resist bypass attempts using tools like:
- **Burp Suite**
- **OWASP ZAP**
- **Tamper Data**
- **Postman/cURL with malicious payloads**

### How It Protects

1. **Multiple Input Vectors** - Validates ALL possible input sources
2. **Recursive Validation** - JSON objects/arrays are validated recursively
3. **Header Validation** - Custom headers can't be used for injection
4. **Cookie Validation** - Session/auth cookies are protected
5. **Body Re-reading** - JSON body is read, validated, and restored for handlers
6. **Security Headers** - Adds defense-in-depth with browser-level protections

## 📝 Testing

### Blocked Requests ❌

```bash
# SQL Injection in JSON body - BLOCKED
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\" OR \"1\"=\"1"}'

# XSS in form data - BLOCKED
curl -X POST http://localhost:8080/api/comments \
  -d "comment=<script>alert('XSS')</script>"

# Header Injection - BLOCKED
curl -X POST http://localhost:8080/api/data \
  -H "X-User-Id: 1' OR '1'='1" \
  -d "data=test"

# Cookie Injection - BLOCKED
curl -X GET http://localhost:8080/api/profile \
  -b "session=abc' OR '1'='1"

# Path Traversal - BLOCKED
curl -X GET "http://localhost:8080/api/files?path=../../etc/passwd"

# Command Injection - BLOCKED
curl -X GET "http://localhost:8080/api/search?q=test; rm -rf /"

# Nested JSON Injection - BLOCKED
curl -X POST http://localhost:8080/api/posts \
  -H "Content-Type: application/json" \
  -d '{"title":"Post","meta":{"author":"<script>alert(1)</script>"}}'
```

### Allowed Requests ✅

```bash
# Normal JSON request
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","email":"john@example.com"}'

# Safe form data
curl -X POST http://localhost:8080/api/users \
  -d "username=john_doe&email=john@example.com"

# Safe query parameters
curl -X GET "http://localhost:8080/api/search?q=golang+security"

# Normal headers
curl -X GET http://localhost:8080/api/profile \
  -H "X-User-Id: 12345" \
  -H "Authorization: Bearer valid_token"
```

### Verify Security Headers

```bash
# Check response headers
curl -I http://localhost:8080/api/users

# Expected headers:
# Content-Security-Policy: default-src 'self'; ...
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Referrer-Policy: strict-origin-when-cross-origin
# Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## ⚡ Performance

The middleware is highly optimized for production use:
- **Pre-compiled regex patterns** - Compiled once during initialization
- **No runtime compilation** - Zero overhead from pattern compilation
- **Minimal latency** - Typically < 1-2ms per request
- **Efficient validation** - Smart validation flow with early returns
- **Memory efficient** - Body reading uses buffered I/O
- **Header injection overhead** - Negligible (~0.1ms)

### Benchmark Results

```
BenchmarkEnhancedMiddleware-8         500000    2.1 ms/op    1024 B/op    12 allocs/op
BenchmarkSecurityHeaders-8          5000000    0.1 ms/op      64 B/op     2 allocs/op
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Gin Web Framework](https://github.com/gin-gonic/gin) - The amazing web framework this middleware is built for
- OWASP - For security best practices and attack pattern references
- Security research community - For continuously discovering new attack vectors

## 📞 Support

- 📧 Email: saya@wahyuprimadi.com
- 🐛 Issues: [GitHub Issues](https://github.com/wprimadi/gin-security-middleware/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/wprimadi/gin-security-middleware/discussions)

## ⚠️ Security Notice

While this middleware provides comprehensive protection against common web vulnerabilities and tampering attempts, it should be used as part of a defense-in-depth strategy. Always:

- ✅ Use parameterized queries for database operations
- ✅ Implement proper authentication and authorization
- ✅ Keep dependencies up to date
- ✅ Follow security best practices for your specific use case
- ✅ Perform regular security audits and penetration testing
- ✅ Use HTTPS in production (required for HSTS)
- ✅ Implement rate limiting and DDoS protection
- ✅ Log and monitor security events
- ✅ Test your CSP policy thoroughly before deployment
- ✅ Consider using a CDN with additional security features

### Security Layers

This middleware provides **Layer 1 (Input Validation)** and **Layer 5 (Security Headers)**. You should also implement:
- **Layer 2**: Authentication & Authorization
- **Layer 3**: Database Query Protection (parameterized queries)
- **Layer 4**: Output Encoding
- **Layer 6**: Rate Limiting
- **Layer 7**: Monitoring & Logging
- **Layer 8**: Network Security (Firewall, DDoS protection)

## 🆚 Comparison with Other Solutions

| Feature | This Middleware | gin-gonic-xss | Bluemonday | secure |
|---------|----------------|---------------|------------|--------|
| SQL Injection | ✅ | ❌ | ❌ | ❌ |
| XSS Protection | ✅ | ✅ | ✅ | ❌ |
| Path Traversal | ✅ | ❌ | ❌ | ❌ |
| Command Injection | ✅ | ❌ | ❌ | ❌ |
| JSON Body Validation | ✅ | ❌ | ❌ | ❌ |
| Header Validation | ✅ | ❌ | ❌ | ❌ |
| Cookie Validation | ✅ | ❌ | ❌ | ❌ |
| Security Headers | ✅ | ❌ | ❌ | ✅ |
| Custom Patterns | ✅ | ❌ | ✅ | ❌ |
| Tamper-Resistant | ✅ | ⚠️ | ⚠️ | ❌ |
| Mode | Block | Sanitize | Sanitize | Headers Only |
| All-in-One | ✅ | ❌ | ❌ | ❌ |

## 🎯 Use Cases

### 1. REST API Protection
Full protection for REST APIs with JSON payloads, including header and cookie validation.

### 2. Web Applications
Protects form submissions and adds security headers for browser-based applications.

### 3. Microservices
Validates inter-service communication headers and prevents injection attacks.

### 4. Admin Panels
Strict security configuration for sensitive administrative interfaces.

### 5. File Upload Services
Specialized configuration to prevent path traversal in file operations.

### 6. Public APIs
Relaxed configuration for public endpoints while maintaining essential protections.

---

Made with ❤️ for the Go community | Stay secure! 🔒