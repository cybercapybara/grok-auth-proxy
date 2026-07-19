package admin

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/moveeeax/grok-auth-proxy/internal/auth"
	"github.com/moveeeax/grok-auth-proxy/internal/store"
)

// Handler serves administrative endpoints.
type Handler struct {
	Store *store.Store
	Auth  *auth.Manager
}

type createKeyRequest struct {
	Name         string   `json:"name"`
	RateLimitRPS *float64 `json:"rate_limit_rps"`
}

// CreateKey POST /admin/keys
func (h *Handler) CreateKey(c *gin.Context) {
	var req createKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		// Allow empty body; reject only malformed JSON with content.
		if c.Request.ContentLength != 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
			return
		}
	}

	res, err := h.Store.CreateKey(req.Name, req.RateLimitRPS)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create key"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"id":             res.Key.ID,
		"name":           res.Key.Name,
		"key_prefix":     res.Key.KeyPrefix,
		"key":            res.Plaintext, // only time plaintext is returned
		"rate_limit_rps": res.Key.RateLimitRPS,
		"created_at":     res.Key.CreatedAt,
		"enabled":        res.Key.Enabled,
	})
}

// ListKeys GET /admin/keys
func (h *Handler) ListKeys(c *gin.Context) {
	keys, err := h.Store.ListKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list keys"})
		return
	}
	out := make([]gin.H, 0, len(keys))
	for _, k := range keys {
		out = append(out, gin.H{
			"id":             k.ID,
			"name":           k.Name,
			"key_prefix":     k.KeyPrefix,
			"rate_limit_rps": k.RateLimitRPS,
			"enabled":        k.Enabled,
			"created_at":     k.CreatedAt,
			"last_used_at":   k.LastUsedAt,
			"revoked_at":     k.RevokedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"keys": out})
}

// RevokeKey DELETE /admin/keys/:id
func (h *Handler) RevokeKey(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing key id"})
		return
	}
	if err := h.Store.RevokeKey(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke key"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "id": id})
}

// ReloadAuth POST /admin/reload-auth
func (h *Handler) ReloadAuth(c *gin.Context) {
	if err := h.Auth.Reload(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reload failed", "detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":     "reloaded",
		"expires_at": h.Auth.ExpiresAt(),
	})
}

// ListAudit GET /admin/audit
// Query: limit, offset, api_key_id, path, model, status_min, status_max, from, to (RFC3339).
func (h *Handler) ListAudit(c *gin.Context) {
	f := store.AuditListFilter{
		APIKeyID: c.Query("api_key_id"),
		Path:     c.Query("path"),
		Model:    c.Query("model"),
	}
	f.Limit = 50
	f.Offset = 0
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}
	if v := c.Query("status_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.StatusMin = &n
		}
	}
	if v := c.Query("status_max"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.StatusMax = &n
		}
	}
	if v := c.Query("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from (use RFC3339)"})
			return
		}
	}
	if v := c.Query("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to (use RFC3339)"})
			return
		}
	}

	rows, total, err := h.Store.ListAuditLogs(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list audit logs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
		"items":  rows,
	})
}

// GetAudit GET /admin/audit/:id
func (h *Handler) GetAudit(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	row, err := h.Store.GetAuditLog(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get audit log"})
		return
	}
	c.JSON(http.StatusOK, row)
}
