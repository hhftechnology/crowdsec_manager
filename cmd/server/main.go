package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/crowdsecurity/crowdsec-manager/internal/backup"
	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/database"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
	"github.com/crowdsecurity/crowdsec-manager/internal/logger"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
	"github.com/crowdsecurity/crowdsec-manager/internal/server"

	// Register all proxy adapters via init().
	_ "github.com/crowdsecurity/crowdsec-manager/internal/proxy/adapters/caddy"
	_ "github.com/crowdsecurity/crowdsec-manager/internal/proxy/adapters/haproxy"
	_ "github.com/crowdsecurity/crowdsec-manager/internal/proxy/adapters/nginx"
	_ "github.com/crowdsecurity/crowdsec-manager/internal/proxy/adapters/standalone"
	_ "github.com/crowdsecurity/crowdsec-manager/internal/proxy/adapters/traefik"
	_ "github.com/crowdsecurity/crowdsec-manager/internal/proxy/adapters/zoraxy"
)

func main() {
	// Load configuration.
	cfg := config.Load()

	// Initialize structured logger.
	logger.Setup(cfg.LogLevel)
	slog.Info("starting crowdsec manager",
		"port", cfg.Port,
		"data_dir", cfg.DataDir,
		"dev_mode", cfg.DevMode,
	)

	// Validate config (non-fatal in dev mode).
	if err := config.Validate(cfg); err != nil {
		if cfg.DevMode {
			slog.Warn("config validation failed (dev mode, continuing)", "error", err)
		} else {
			slog.Error("config validation failed", "error", err)
			os.Exit(1)
		}
	}

	// Initialize database.
	db, err := database.New(cfg.DataDir)
	if err != nil {
		slog.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Initialize Docker client.
	dockerClient, err := docker.NewClient()
	if err != nil {
		if cfg.DevMode {
			slog.Warn("docker client unavailable (dev mode, continuing)", "error", err)
		} else {
			slog.Error("failed to initialize docker client", "error", err)
			os.Exit(1)
		}
	}

	// Initialize proxy manager.
	proxyMgr := proxy.NewManager(cfg, dockerClient, db)
	if dockerClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := proxyMgr.Initialize(ctx); err != nil {
			slog.Warn("proxy manager initialization failed", "error", err)
		}
		cancel()
	}

	// Build dependencies.
	deps := &api.Dependencies{
		Docker:        dockerClient,
		DB:            db,
		Config:        cfg,
		ProxyManager:  proxyMgr,
		BackupManager: backup.NewManager(cfg, dockerClient, db),
	}

	// Create the HTTP server.
	handler := server.New(deps)
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine.
	go func() {
		slog.Info("server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("shutting down", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("forced shutdown", "error", err)
	}

	slog.Info("server stopped")
}
