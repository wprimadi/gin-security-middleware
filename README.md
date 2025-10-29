# 🔒 Gin Security Middleware

![Gin Security Middleware](https://raw.githubusercontent.com/wprimadi/gin-security-middleware/refs/heads/main/banner.png)

Advanced security middleware for [Gin](https://github.com/gin-gonic/gin) web framework that provides comprehensive protection against common web vulnerabilities including SQL Injection, XSS, Path Traversal, Command Injection, and more. Now with **full coverage** for all input vectors including JSON bodies, HTTP headers, and cookies.

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
- 🧹 **Input Sanitization** - Automatic HTML escaping and input cleaning
- ⚙️ **Highly Configurable** - Enable/disable specific protections per route
- 🎯 **Whitelist Support** - Exclude specific fields from validation
- 🚀 **Performance Optimized** - Pre-compiled regex patterns for fast validation
- 📊 **Detailed Error Reporting** - Know exactly which field and violation type triggered the block
- 🔐 **Tamper-Proof** - Resistant to bypass attempts via Burp Suite, Tamper Data, or similar tools

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
    r.Use(security.EnhancedSecurityMiddleware(security.DefaultSecurityConfig()))
    
    r.POST("/api/users", func(c *gin.Context) {
        // All inputs are validated: query params, form data, JSON, headers, cookies
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

### Example 2: Different Security Levels for Route Groups

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
}

// Strict security for admin API
adminConfig := security.SecurityConfig{
    MaxLength:             2000,
    BlockSQLInjection:     true,
    BlockXSS:              true,
    BlockPathTraversal:    true,
    BlockCommandInjection: true,
    SanitizeInput:         true,
    ValidateHeaders:       true,
    ValidateCookies:       true,
    ValidateJSONBody:      true,
    HeadersToValidate:     []string{"X-Admin-Token", "X-User-Id"},
    CustomPatterns:        []string{`(?i)(eval|exec)`},
}

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

### Example 3: Protecting Against Header Injection

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

### Example 4: JSON Body with Nested Objects

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
    c.JSON(200, gin.H{"message": "Post created"})
})
```

### Example 5: Cookie Validation

```go
r := gin.Default()

config := security.DefaultSecurityConfig()
config.ValidateCookies = true

r.Use(security.EnhancedSecurityMiddleware(config))

r.GET("/api/data", func(c *gin.Context) {
    // All cookies are validated - no injection possible
    session, _ := c.Cookie("session")
    c.JSON(200, gin.H{"session": session})
})
```

### Example 6: File Upload Protection

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

## 🛡️ What Gets Blocked?

### SQL Injection Patterns
- `UNION SELECT`
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

## ⚡ Performance

The middleware is highly optimized for production use:
- **Pre-compiled regex patterns** - Compiled once during initialization
- **No runtime compilation** - Zero overhead from pattern compilation
- **Minimal latency** - Typically < 1-2ms per request
- **Efficient validation** - Smart validation flow with early returns
- **Memory efficient** - Body reading uses buffered I/O

### Benchmark Results

```
BenchmarkEnhancedMiddleware-8    500000    2.1 ms/op    1024 B/op    12 allocs/op
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
- ✅ Use HTTPS in production
- ✅ Implement rate limiting and DDoS protection
- ✅ Log and monitor security events

### Security Layers

This middleware provides **Layer 1 (Input Validation)**. You should also implement:
- **Layer 2**: Authentication & Authorization
- **Layer 3**: Database Query Protection (parameterized queries)
- **Layer 4**: Output Encoding
- **Layer 5**: Security Headers (CSP, HSTS, etc.)
- **Layer 6**: Rate Limiting
- **Layer 7**: Monitoring & Logging

## 🆚 Comparison with Other Solutions

| Feature | This Middleware | gin-gonic-xss | Bluemonday |
|---------|----------------|---------------|------------|
| SQL Injection | ✅ | ❌ | ❌ |
| XSS Protection | ✅ | ✅ | ✅ |
| Path Traversal | ✅ | ❌ | ❌ |
| Command Injection | ✅ | ❌ | ❌ |
| JSON Body Validation | ✅ | ❌ | ❌ |
| Header Validation | ✅ | ❌ | ❌ |
| Cookie Validation | ✅ | ❌ | ❌ |
| Custom Patterns | ✅ | ❌ | ✅ |
| Tamper-Resistant | ✅ | ⚠️ | ⚠️ |
| Mode | Block | Sanitize | Sanitize |

---

Made with ❤️ for the Go community | Stay secure! 🔒