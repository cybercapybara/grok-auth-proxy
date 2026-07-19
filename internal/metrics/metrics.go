package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds Prometheus collectors.
type Metrics struct {
	Requests *prometheus.CounterVec
	Latency  *prometheus.HistogramVec

	// Auth / Grok session
	AuthTokenExpiresAt       prometheus.Gauge
	AuthTokenSecondsRemaining prometheus.Gauge
	AuthTokenHasRefresh      prometheus.Gauge
	AuthReady                prometheus.Gauge
	AuthRefreshTotal         *prometheus.CounterVec
}

// New registers default metrics.
func New() *Metrics {
	return &Metrics{
		Requests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "gap_http_requests_total",
			Help: "Total HTTP requests handled by grok-auth-proxy",
		}, []string{"method", "path", "status"}),
		Latency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "gap_http_request_duration_seconds",
			Help:    "HTTP request latency",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path"}),

		AuthTokenExpiresAt: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gap_auth_token_expires_at_seconds",
			Help: "Unix timestamp when the current Grok access token expires (0 if unknown)",
		}),
		AuthTokenSecondsRemaining: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gap_auth_token_seconds_remaining",
			Help: "Seconds until the Grok access token expires (negative if already expired)",
		}),
		AuthTokenHasRefresh: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gap_auth_token_has_refresh",
			Help: "1 if a refresh_token is available, else 0",
		}),
		AuthReady: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gap_auth_ready",
			Help: "1 if a non-empty access token is loaded, else 0",
		}),
		AuthRefreshTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "gap_auth_refresh_total",
			Help: "OIDC token refresh attempts",
		}, []string{"result"}), // success|error
	}
}

// SetAuthState updates gauges from the auth manager state.
func (m *Metrics) SetAuthState(ready bool, expiresAt time.Time, hasRefresh bool) {
	if ready {
		m.AuthReady.Set(1)
	} else {
		m.AuthReady.Set(0)
	}
	if hasRefresh {
		m.AuthTokenHasRefresh.Set(1)
	} else {
		m.AuthTokenHasRefresh.Set(0)
	}
	if expiresAt.IsZero() {
		m.AuthTokenExpiresAt.Set(0)
		m.AuthTokenSecondsRemaining.Set(0)
		return
	}
	m.AuthTokenExpiresAt.Set(float64(expiresAt.Unix()))
	m.AuthTokenSecondsRemaining.Set(time.Until(expiresAt).Seconds())
}

// IncAuthRefresh increments refresh counter.
func (m *Metrics) IncAuthRefresh(success bool) {
	if success {
		m.AuthRefreshTotal.WithLabelValues("success").Inc()
	} else {
		m.AuthRefreshTotal.WithLabelValues("error").Inc()
	}
}

// Middleware records request metrics.
func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		status := strconv.Itoa(c.Writer.Status())
		m.Requests.WithLabelValues(c.Request.Method, path, status).Inc()
		m.Latency.WithLabelValues(c.Request.Method, path).Observe(time.Since(start).Seconds())
	}
}

// Handler returns the Prometheus scrape handler.
func Handler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
