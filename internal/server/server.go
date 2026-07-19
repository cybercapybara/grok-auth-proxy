package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/cybercapybara/grok-auth-proxy/internal/auth"
	"github.com/cybercapybara/grok-auth-proxy/internal/config"
	"github.com/cybercapybara/grok-auth-proxy/internal/handlers/admin"
	"github.com/cybercapybara/grok-auth-proxy/internal/handlers/health"
	"github.com/cybercapybara/grok-auth-proxy/internal/metrics"
	"github.com/cybercapybara/grok-auth-proxy/internal/middleware"
	"github.com/cybercapybara/grok-auth-proxy/internal/proxy"
	"github.com/cybercapybara/grok-auth-proxy/internal/store"
)

// Server wires HTTP routes and dependencies.
type Server struct {
	cfg    *config.Config
	log    *zap.Logger
	engine *gin.Engine
	http   *http.Server
	auth   *auth.Manager
	store  *store.Store
}

// Dependencies bundles constructor inputs.
type Dependencies struct {
	Config *config.Config
	Log    *zap.Logger
	Auth   *auth.Manager
	Store  *store.Store
}

// New builds the HTTP server.
func New(deps Dependencies) (*Server, error) {
	if deps.Log == nil {
		deps.Log = zap.NewNop()
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.RequestID())
	r.Use(middleware.AccessLog(deps.Log, deps.Config.Log.Redact))
	r.Use(middleware.CORS(deps.Config.CORS.AllowedOrigins))

	var m *metrics.Metrics
	if deps.Config.Metrics.Enabled {
		m = metrics.New()
		r.Use(m.Middleware())
		r.GET(deps.Config.Metrics.Path, metrics.Handler())
	}

	up, err := proxy.NewWithOptions(proxy.Options{
		BaseURL:      deps.Config.Auth.UpstreamBase,
		Tokens:       deps.Auth,
		Log:          deps.Log,
		Auditor:      deps.Store,
		AuditEnabled: deps.Config.Audit.Enabled,
		MaxBodyBytes: deps.Config.Audit.MaxBodyBytes,
	})
	if err != nil {
		return nil, err
	}

	healthH := &health.Handler{Auth: deps.Auth, Store: deps.Store}
	r.GET("/health", healthH.Health)
	r.GET("/ready", healthH.Ready)

	rl := middleware.NewRateLimiter(deps.Config.RateLimit.RPS, deps.Config.RateLimit.Burst)

	v1 := r.Group("/v1")
	v1.Use(middleware.APIKeyAuth(deps.Store))
	v1.Use(rl.Middleware())
	{
		// Explicit routes for OpenAI-compatible paths.
		v1.POST("/chat/completions", up.Handler())
		v1.GET("/models", up.Handler())
		v1.POST("/completions", up.Handler())
		v1.POST("/embeddings", up.Handler())
		v1.POST("/responses", up.Handler())
	}

	adminH := &admin.Handler{Store: deps.Store, Auth: deps.Auth}
	ad := r.Group("/admin")
	ad.Use(middleware.AdminAuth(deps.Config.Server.AdminKey))
	{
		ad.POST("/keys", adminH.CreateKey)
		ad.GET("/keys", adminH.ListKeys)
		ad.DELETE("/keys/:id", adminH.RevokeKey)
		ad.POST("/reload-auth", adminH.ReloadAuth)
		ad.GET("/audit", adminH.ListAudit)
		ad.GET("/audit/:id", adminH.GetAudit)
	}

	srv := &http.Server{
		Addr:              deps.Config.Server.Addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		// WriteTimeout left zero for long-lived SSE streams
	}

	return &Server{
		cfg:    deps.Config,
		log:    deps.Log,
		engine: r,
		http:   srv,
		auth:   deps.Auth,
		store:  deps.Store,
	}, nil
}

// Engine exposes the gin engine (for tests).
func (s *Server) Engine() *gin.Engine {
	return s.engine
}

// Run starts listening until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("listening", zap.String("addr", s.cfg.Server.Addr))
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownTimeout)
		defer cancel()
		s.log.Info("shutting down")
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}
