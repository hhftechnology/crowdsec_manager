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
	"crowdsec-manager/internal/backup"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger.Init(cfg.LogLevel, cfg.LogFile)

	// Initialize database
	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		logger.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()
	logger.Info("Database initialized", "path", cfg.DatabasePath)

	// Initialize Docker client
	dockerClient, err := docker.NewClient()
	if err != nil {
		logger.Fatal("Failed to initialize Docker client", "error", err)
	}
	defer dockerClient.Close()

	// Check prerequisites
	if err := checkPrerequisites(dockerClient); err != nil {
		logger.Fatal("Prerequisites check failed", "error", err)
	}

	// Initialize backup manager
	backupManager := backup.NewManager(cfg.BackupDir, cfg.RetentionDays)

	// Setup Gin router
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.GinLogger())

	// CORS configuration
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API routes
	apiGroup := router.Group("/api")
	{
		api.RegisterHealthRoutes(apiGroup, dockerClient, db)
		api.RegisterIPRoutes(apiGroup, dockerClient)
		api.RegisterWhitelistRoutes(apiGroup, dockerClient)
		api.RegisterScenarioRoutes(apiGroup, dockerClient)
		api.RegisterCaptchaRoutes(apiGroup, dockerClient)
		api.RegisterLogRoutes(apiGroup, dockerClient, db)
		api.RegisterBackupRoutes(apiGroup, backupManager, dockerClient)
		api.RegisterUpdateRoutes(apiGroup, dockerClient)
		api.RegisterCronRoutes(apiGroup)
		api.RegisterServicesRoutes(apiGroup, dockerClient, db)
	}

	// Serve static files (built frontend)
	router.Static("/assets", "./web/dist/assets")
	router.StaticFile("/", "./web/dist/index.html")
	router.NoRoute(func(c *gin.Context) {
		c.File("./web/dist/index.html")
	})

	// Create server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Starting server", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	}

	logger.Info("Server exited")
}

func checkPrerequisites(client *docker.Client) error {
	logger.Info("Checking prerequisites...")

	// Check Docker daemon
	if err := client.Ping(); err != nil {
		return fmt.Errorf("docker daemon not running: %w", err)
	}
	logger.Info(" Docker daemon is running")

	// Check required containers exist
	containers := []string{"crowdsec", "traefik", "pangolin", "gerbil"}
	for _, name := range containers {
		exists, err := client.ContainerExists(name)
		if err != nil {
			logger.Warn("Failed to check container", "name", name, "error", err)
			continue
		}
		if exists {
			logger.Info(" Container exists", "name", name)
		} else {
			logger.Warn(" Container not found", "name", name)
		}
	}

	return nil
}
