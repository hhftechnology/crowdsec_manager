package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"crowdsec-manager/internal/api"
	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/api/middleware"
	"crowdsec-manager/internal/backup"
	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/configvalidator"
	"crowdsec-manager/internal/cron"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/history"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/messaging"
)

// Main entry point for the CrowdSec Manager server
// Initializes all components and starts the HTTP server with graceful shutdown

func main() {
	// Load configuration from environment variables
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize structured logger with configured level and output file
	logger.Init(cfg.LogLevel, cfg.LogFile)
	defer logger.Sync()

	// Initialize SQLite database connection with automatic schema migration
	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		logger.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()
	logger.Info("Database initialized", "path", cfg.DatabasePath)

	historyStore, err := history.NewStore(cfg.HistoryDatabasePath)
	if err != nil {
		logger.Fatal("Failed to initialize history database", "error", err)
	}
	defer historyStore.Close()
	logger.Info("History database initialized", "path", cfg.HistoryDatabasePath)

	// Initialize multi-host Docker client (falls back to single host if DOCKER_HOSTS is empty)
	multiHost, err := docker.NewMultiHostClient(cfg.DockerHosts)
	if err != nil {
		logger.Fatal("Failed to initialize Docker client", "error", err)
	}
	defer multiHost.Close()

	// Default client for backward compatibility with existing handler signatures
	dockerClient := multiHost.DefaultClient()

	dataDir := cfg.ConfigDir

	// Initialize backup manager with 7-day retention for automated cleanup
	backupManager := backup.NewManager(filepath.Join(dataDir, "backups"), 7)

	// Initialize cron scheduler for recurring tasks (e.g., automated backups)
	cronScheduler := cron.NewScheduler(filepath.Join(dataDir, "cron.json"), backupManager)
	cronScheduler.Start()
	defer cronScheduler.Stop()

	// Initialize WebSocket/SSE hub (always available for real-time events)
	hub := messaging.NewHub()
	go hub.Run()
	defer hub.Stop()

	historyService := history.NewService(historyStore, dockerClient, cfg, hub)
	historyService.Start()
	defer historyService.Stop()
	handlers.SetHistoryService(historyService)

	// Initialize config validator for drift detection and recovery
	validator := configvalidator.NewValidator(db, dockerClient, hub, cfg)
	handlers.SetConfigValidator(validator)

	// Snapshot all configs on startup (populates DB if empty)
	validator.SnapshotAll()

	// Validate configs and warn about drift
	if report := validator.ValidateAll(); report.Overall != "ok" {
		logger.Warn("Config drift detected on startup", "overall", report.Overall)
	}

	// Initialize NATS messaging (optional — nil-safe when disabled)
	publisher, natsCleanup := initMessaging(cfg, hub)
	if natsCleanup != nil {
		defer natsCleanup()
	}

	// Configure HTTP router with recovery middleware and custom logger
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.GinLogger())

	// Configure CORS – allow all origins so the Capacitor mobile app
	// (which runs from capacitor://localhost or https://localhost) can
	// reach the API alongside browser-based frontends.
	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Docker-Host"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	// Basic health check endpoint for container orchestration
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Register all API route groups under /api prefix
	apiGroup := router.Group("/api")

	// Add rate limiting middleware (100 requests per minute per IP)
	apiGroup.Use(middleware.RateLimiter(100))

	// Add Docker host selector middleware for multi-host support
	apiGroup.Use(middleware.DockerHostSelector(multiHost))

	{
		api.RegisterHealthRoutes(apiGroup, dockerClient, db, cfg)
		api.RegisterIPRoutes(apiGroup, dockerClient, cfg)
		api.RegisterWhitelistRoutes(apiGroup, dockerClient, cfg)
		api.RegisterAllowlistRoutes(apiGroup, dockerClient, cfg)
		api.RegisterScenarioRoutes(apiGroup, dockerClient, cfg.ConfigDir, cfg)
		api.RegisterCaptchaRoutes(apiGroup, dockerClient, db, cfg)
		api.RegisterLogRoutes(apiGroup, dockerClient, db, cfg)
		api.RegisterBackupRoutes(apiGroup, backupManager, dockerClient)
		api.RegisterUpdateRoutes(apiGroup, dockerClient, cfg)
		api.RegisterCronRoutes(apiGroup, cronScheduler)
		ttlCache := cache.New()
		api.RegisterServicesRoutes(apiGroup, dockerClient, db, cfg, ttlCache)
		api.RegisterNotificationRoutes(apiGroup, dockerClient, db, cfg)
		api.RegisterProfileRoutes(apiGroup, db, cfg, dockerClient)
		api.RegisterHostRoutes(apiGroup, multiHost)
		api.RegisterTerminalRoutes(apiGroup, dockerClient)

		// Hub browser routes
		api.RegisterHubRoutes(apiGroup, dockerClient, db, cfg)

		// Simulation mode routes
		api.RegisterSimulationRoutes(apiGroup, dockerClient, cfg)

		// Event routes (hub is always available for SSE/WebSocket)
		api.RegisterEventRoutes(apiGroup, hub)

		// Config validation routes
		api.RegisterConfigValidationRoutes(apiGroup, validator)
	}

	// Bridge NATS events to WebSocket hub (if both are available)
	if publisher != nil && hub != nil {
		go bridgeNATSToHub(cfg, hub)
	}
	// Suppress unused variable warnings — publisher will be used by handlers in Phase 4
	_ = publisher

	// Serve React frontend static assets and handle client-side routing.
	// Assets use content-hashed filenames so they can be cached indefinitely.
	router.Static("/assets", "./web/dist/assets")
	// index.html must not be cached — it references hashed asset URLs that
	// change on each build. Without no-cache the browser may serve a stale
	// copy (304) that points to old, non-existent JS chunks.
	serveIndex := func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.File("./web/dist/index.html")
	}
	router.GET("/", func(c *gin.Context) { serveIndex(c) })
	router.NoRoute(serveIndex)

	// Create HTTP server with production-ready timeouts to prevent resource exhaustion
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTP server in background goroutine to allow for graceful shutdown handling
	go func() {
		logger.Info("Starting server", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	// Set up signal handling for graceful shutdown (SIGINT from Ctrl+C or SIGTERM from container orchestrator)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Perform graceful shutdown with 30-second timeout to allow in-flight requests to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	}

	logger.Info("Server exited")
}

// initMessaging initializes NATS client and publisher.
// Returns nil values when NATS is disabled — all are nil-safe.
func initMessaging(cfg *config.Config, hub *messaging.Hub) (*messaging.Publisher, func()) {
	if !cfg.NatsEnabled || cfg.NatsURL == "" {
		logger.Info("NATS messaging disabled")
		return nil, nil
	}

	natsClient, err := messaging.NewClient(cfg.NatsURL, cfg.NatsToken)
	if err != nil {
		logger.Error("Failed to connect to NATS (messaging disabled)", "error", err)
		return nil, nil
	}

	publisher := messaging.NewPublisher(natsClient)

	logger.Info("NATS messaging initialized", "url", cfg.NatsURL)

	cleanup := func() {
		natsClient.Close()
	}
	return publisher, cleanup
}

// bridgeNATSToHub subscribes to NATS subjects and forwards events to the WebSocket hub
func bridgeNATSToHub(cfg *config.Config, hub *messaging.Hub) {
	// This will be wired up when NATS client Subscribe is implemented
	logger.Info("NATS-to-WebSocket bridge started")
}

// checkPrerequisites verifies that Docker daemon is running and required containers exist
// This function is defined but not currently called in main - consider adding prerequisite checks if needed
func checkPrerequisites(client *docker.Client, cfg *config.Config) error {
	logger.Info("Checking prerequisites...")

	// Verify Docker daemon connectivity
	if err := client.Ping(); err != nil {
		return fmt.Errorf("docker daemon not running: %w", err)
	}
	logger.Info("  Docker daemon is running")

	// Verify existence of required containers (they may not be running yet)
	containers := []string{cfg.CrowdsecContainerName, cfg.TraefikContainerName, cfg.PangolinContainerName, cfg.GerbilContainerName}
	for _, name := range containers {
		exists, err := client.ContainerExists(name)
		if err != nil {
			logger.Warn("Failed to check container", "name", name, "error", err)
			continue
		}
		if exists {
			logger.Info("  Container exists", "name", name)
		} else {
			logger.Warn("  Container not found", "name", name)
		}
	}

	return nil
}
