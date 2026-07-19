package health

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/moveeeax/grok-auth-proxy/internal/auth"
	"github.com/moveeeax/grok-auth-proxy/internal/store"
)

// Handler serves liveness and readiness probes.
type Handler struct {
	Auth  *auth.Manager
	Store *store.Store
}

// Health is a liveness probe (process is up).
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Ready is a readiness probe (auth loaded + DB reachable).
func (h *Handler) Ready(c *gin.Context) {
	if h.Auth == nil || !h.Auth.Ready() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "reason": "auth"})
		return
	}
	if h.Store != nil {
		if err := h.Store.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "reason": "db"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":     "ready",
		"expires_at": h.Auth.ExpiresAt(),
	})
}
