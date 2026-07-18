package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/cybercapybara/grok-auth-proxy/internal/store"
)

const (
	ContextAPIKey    = "api_key"
	ContextRequestID = "request_id"
	HeaderRequestID  = "X-Request-ID"
)

// RequestID injects or propagates a request ID.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(HeaderRequestID)
		if id == "" {
			id = uuid.NewString()
		}
		c.Set(ContextRequestID, id)
		c.Writer.Header().Set(HeaderRequestID, id)
		c.Next()
	}
}

// AccessLog writes a structured access log line after each request.
func AccessLog(log *zap.Logger, redact bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		path := c.Request.URL.Path
		fields := []zap.Field{
			zap.String("request_id", c.GetString(ContextRequestID)),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
		}
		if !redact {
			if auth := c.GetHeader("Authorization"); auth != "" {
				fields = append(fields, zap.String("authorization", maskBearer(auth)))
			}
		}
		if c.Writer.Status() >= 500 {
			log.Error("request", fields...)
		} else if c.Writer.Status() >= 400 {
			log.Warn("request", fields...)
		} else {
			log.Info("request", fields...)
		}
	}
}

func maskBearer(h string) string {
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return "***"
	}
	tok := h[len(p):]
	if len(tok) <= 12 {
		return p + "***"
	}
	return p + tok[:8] + "…"
}

// CORS sets simple CORS headers from allowed origins.
func CORS(allowed []string) gin.HandlerFunc {
	allowAll := len(allowed) == 0 || (len(allowed) == 1 && allowed[0] == "*")
	set := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		set[o] = struct{}{}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if allowAll {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if origin != "" {
			if _, ok := set[origin]; ok {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			}
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Admin-Key, X-Request-ID")
		c.Header("Access-Control-Expose-Headers", "X-Request-ID")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// APIKeyAuth validates Bearer tokens against the store.
func APIKeyAuth(s *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := extractBearer(c)
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"message": "missing API key", "type": "invalid_request_error"},
			})
			return
		}
		key, err := s.ValidatePlaintext(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"message": "invalid API key", "type": "invalid_request_error"},
			})
			return
		}
		c.Set(ContextAPIKey, key)
		c.Next()
	}
}

// AdminAuth checks the admin key via Bearer or X-Admin-Key.
func AdminAuth(adminKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		got := c.GetHeader("X-Admin-Key")
		if got == "" {
			got = extractBearer(c)
		}
		if got == "" || got != adminKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
			})
			return
		}
		c.Next()
	}
}

func extractBearer(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if h == "" {
		return ""
	}
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

// RateLimiter is an in-memory per-key token bucket limiter.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rps      float64
	burst    int
}

// NewRateLimiter creates a rate limiter with global defaults.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rps,
		burst:    burst,
	}
}

func (rl *RateLimiter) get(key string, customRPS *float64) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if lim, ok := rl.limiters[key]; ok {
		return lim
	}
	rps := rl.rps
	burst := rl.burst
	if customRPS != nil && *customRPS > 0 {
		rps = *customRPS
		burst = int(*customRPS * 2)
		if burst < 1 {
			burst = 1
		}
	}
	lim := rate.NewLimiter(rate.Limit(rps), burst)
	rl.limiters[key] = lim
	return lim
}

// Middleware enforces per-API-key rate limits (must run after APIKeyAuth).
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		val, ok := c.Get(ContextAPIKey)
		if !ok {
			c.Next()
			return
		}
		key, ok := val.(*store.APIKey)
		if !ok || key == nil {
			c.Next()
			return
		}
		lim := rl.get(key.ID, key.RateLimitRPS)
		if !lim.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": gin.H{"message": "rate limit exceeded", "type": "rate_limit_error"},
			})
			return
		}
		c.Next()
	}
}
