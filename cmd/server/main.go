package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"crowdsec-manager/internal/api"
	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/api/middleware"
	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/history"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/messaging"
)

// Main entry point for the CrowdSec Manager server
// Initializes all components and starts the HTTP server with graceful shutdown

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger.Init(cfg.LogLevel, cfg.LogFile)
	defer logger.Sync()

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

	multiHost, err := docker.NewMultiHostClient(cfg.DockerHosts)
	if err != nil {
		logger.Fatal("Failed to initialize Docker client", "error", err)
	}
	defer multiHost.Close()

	dockerClient := multiHost.DefaultClient()

	hub := messaging.NewHub()
	go hub.Run()
	defer hub.Stop()

	historyService := history.NewService(historyStore, dockerClient, cfg, hub)
	historyService.Start()
	defer historyService.Stop()
	handlers.SetHistoryService(historyService)

	publisher, natsCleanup := initMessaging(cfg, hub)
	if natsCleanup != nil {
		defer natsCleanup()
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.GinLogger())

	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Docker-Host"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	apiGroup := router.Group("/api")
	apiGroup.Use(middleware.RateLimiter(100))
	apiGroup.Use(middleware.DockerHostSelector(multiHost))

	{
		api.RegisterHealthRoutes(apiGroup, dockerClient, cfg)
		api.RegisterAllowlistRoutes(apiGroup, dockerClient, cfg)
		api.RegisterScenarioRoutes(apiGroup, dockerClient, cfg.ConfigDir, cfg)
		api.RegisterLogRoutes(apiGroup, dockerClient, cfg)
		ttlCache := cache.New()
		api.RegisterServicesRoutes(apiGroup, dockerClient, db, cfg, ttlCache)
		api.RegisterHostRoutes(apiGroup, multiHost)
		api.RegisterTerminalRoutes(apiGroup, dockerClient)

		api.RegisterHubRoutes(apiGroup, dockerClient, db, cfg)
		api.RegisterSimulationRoutes(apiGroup, dockerClient, cfg)
		api.RegisterEventRoutes(apiGroup, hub)
	}

	if publisher != nil && hub != nil {
		go bridgeNATSToHub(cfg, hub)
	}
	_ = publisher

	router.Static("/assets", "./web/dist/assets")
	serveIndex := func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.File("./web/dist/index.html")
	}
	router.GET("/", func(c *gin.Context) { serveIndex(c) })
	router.NoRoute(serveIndex)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("Starting server", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

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

	if err := client.Ping(); err != nil {
		return fmt.Errorf("docker daemon not running: %w", err)
	}
	logger.Info("  Docker daemon is running")

	containers := []string{cfg.CrowdsecContainerName}
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
