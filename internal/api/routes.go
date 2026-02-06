package api

import (
	"github.com/gin-gonic/gin"
)

// RegisterAll registers all API route groups under the given router group.
// Each domain has its own route registration function in a separate file (routes_*.go).
// This keeps the central registration thin and each domain self-contained.
func RegisterAll(router *gin.RouterGroup, deps *Dependencies) {
	registerHealthRoutes(router, deps)
	registerIPRoutes(router, deps)
	registerWhitelistRoutes(router, deps)
	registerAllowlistRoutes(router, deps)
	registerScenarioRoutes(router, deps)
	registerCaptchaRoutes(router, deps)
	registerLogRoutes(router, deps)
	registerBackupRoutes(router, deps)
	registerUpdateRoutes(router, deps)
	registerServicesRoutes(router, deps)
	registerCrowdSecRoutes(router, deps)
	registerTraefikRoutes(router, deps)  // Legacy routes with deprecation headers
	registerConfigRoutes(router, deps)
	registerNotificationRoutes(router, deps)
	registerCronRoutes(router, deps)
	registerProfileRoutes(router, deps)
	registerProxyRoutes(router, deps)
	registerAddonRoutes(router, deps)
	registerValidationRoutes(router, deps)
}
