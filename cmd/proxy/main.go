package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/cybercapybara/grok-auth-proxy/internal/auth"
	"github.com/cybercapybara/grok-auth-proxy/internal/config"
	"github.com/cybercapybara/grok-auth-proxy/internal/server"
	"github.com/cybercapybara/grok-auth-proxy/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	log, err := newLogger(cfg.Log.Level)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer func() { _ = log.Sync() }()

	st, err := store.Open(cfg.DB.Driver, cfg.DB.DSN)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() { _ = st.Close() }()

	authMgr, err := auth.NewManager(auth.Options{
		Path:        cfg.Auth.File,
		Issuer:      cfg.Auth.Issuer,
		ClientID:    cfg.Auth.ClientID,
		Account:     cfg.Auth.Account,
		RefreshSkew: cfg.Auth.RefreshSkew,
		Log:         log.Named("auth"),
	})
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if err := authMgr.StartWatch(); err != nil {
		log.Warn("auth file watch disabled", zap.Error(err))
	}
	defer func() { _ = authMgr.Close() }()

	srv, err := server.New(server.Dependencies{
		Config: cfg,
		Log:    log,
		Auth:   authMgr,
		Store:  st,
	})
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return srv.Run(ctx)
}

func newLogger(level string) (*zap.Logger, error) {
	var lvl zapcore.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = zapcore.DebugLevel
	case "warn":
		lvl = zapcore.WarnLevel
	case "error":
		lvl = zapcore.ErrorLevel
	default:
		lvl = zapcore.InfoLevel
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.Encoding = "json"
	return cfg.Build()
}
