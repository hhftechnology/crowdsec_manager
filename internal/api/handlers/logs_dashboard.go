package handlers

import (
	"fmt"
	"net/http"
	"time"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/geoip"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/logs/aggregate"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

type dashboardLogReader interface {
	ExecCommand(containerName string, cmd []string) (string, error)
	GetContainerLogs(containerName string, tail string) (string, error)
}

type serviceDashboardHandlerInput struct {
	Reader   dashboardLogReader
	Database *database.Database
	Config   *config.Config
	Geo      *geoip.Resolver
	Cache    *cache.TTLCache
}

type traefikLogReadInput struct {
	Reader   dashboardLogReader
	Database *database.Database
	Config   *config.Config
	Tail     string
}

// rangeTailMap maps each preset to a max-tail size that bounds memory.
// Anything older than the timestamp cutoff is filtered downstream.
var rangeTailMap = map[models.DashboardRange]string{
	models.Range5m:  "2000",
	models.Range1h:  "10000",
	models.Range6h:  "30000",
	models.Range24h: "60000",
}

func rangeDuration(rng models.DashboardRange) time.Duration {
	switch rng {
	case models.Range5m:
		return 5 * time.Minute
	case models.Range1h:
		return time.Hour
	case models.Range6h:
		return 6 * time.Hour
	case models.Range24h:
		return 24 * time.Hour
	default:
		return time.Hour
	}
}

func parseDashboardRange(raw string) (models.DashboardRange, bool) {
	r := models.DashboardRange(raw)
	if _, ok := rangeTailMap[r]; ok {
		return r, true
	}
	return "", false
}

// geoAdapter exposes *geoip.Resolver as aggregate.GeoLookup without the
// aggregate package importing geoip (which would create a cycle in tests).
type geoAdapter struct{ r *geoip.Resolver }

func (a geoAdapter) Lookup(ip string) (aggregate.Location, bool) {
	if a.r == nil {
		return aggregate.Location{}, false
	}
	loc, ok := a.r.Lookup(ip)
	if !ok {
		return aggregate.Location{}, false
	}
	return aggregate.Location{Country: loc.Country, Lat: loc.Lat, Lng: loc.Lng}, true
}

// AnalyzeServiceDashboard returns a service-shaped dashboard payload.
// Supports :service in {traefik, crowdsec}.
func AnalyzeServiceDashboard(dockerClient *docker.Client, db *database.Database, cfg *config.Config, geo *geoip.Resolver, ttlCache ...*cache.TTLCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		handler := analyzeServiceDashboardWithReader(serviceDashboardHandlerInput{
			Reader:   resolveDockerClient(c, dockerClient),
			Database: db,
			Config:   cfg,
			Geo:      geo,
			Cache:    optionalCache(ttlCache),
		})
		handler(c)
	}
}

func analyzeServiceDashboardWithReader(input serviceDashboardHandlerInput) gin.HandlerFunc {
	adapter := geoAdapter{r: input.Geo}
	return func(c *gin.Context) {
		service := c.Param("service")

		rngRaw := c.DefaultQuery("range", string(models.Range1h))
		rng, ok := parseDashboardRange(rngRaw)
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("invalid range %q (allowed: 5m,1h,6h,24h)", rngRaw),
			})
			return
		}

		if service != "traefik" && service != "crowdsec" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("unsupported service %q (expected traefik or crowdsec)", service),
			})
			return
		}

		tail := rangeTailMap[rng]
		cacheKey := serviceDashboardCacheKey(c, service)
		if input.Cache != nil {
			if cached, ok := input.Cache.Get(cacheKey); ok {
				c.JSON(http.StatusOK, models.Response{Success: true, Data: cached})
				return
			}
		}

		now := time.Now().UTC()
		since := now.Add(-rangeDuration(rng))

		switch service {
		case "traefik":
			rawLogs, err := readTraefikLogs(traefikLogReadInput{
				Reader:   input.Reader,
				Database: input.Database,
				Config:   input.Config,
				Tail:     tail,
			})
			if err != nil {
				logger.Warn("failed to read traefik logs for dashboard", "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("failed to read traefik logs: %v", err),
				})
				return
			}
			data := aggregate.BucketTraefikRaw(rawLogs, since, now, rng, adapter)
			if input.Cache != nil {
				input.Cache.Set(cacheKey, data, serviceDashboardCacheTTL)
			}
			c.JSON(http.StatusOK, models.Response{Success: true, Data: data})

		case "crowdsec":
			parser := docker.NewLogParser()
			rawLogs, err := input.Reader.GetContainerLogs(input.Config.CrowdsecContainerName, tail)
			if err != nil {
				logger.Warn("failed to read crowdsec logs for dashboard", "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("failed to read crowdsec logs: %v", err),
				})
				return
			}
			entries := parser.Parse(rawLogs, "crowdsec")
			data := aggregate.BucketCrowdSec(entries, since, now, rng, adapter)
			if input.Cache != nil {
				input.Cache.Set(cacheKey, data, serviceDashboardCacheTTL)
			}
			c.JSON(http.StatusOK, models.Response{Success: true, Data: data})

		}
	}
}

// readTraefikLogs prefers the access log file inside the Traefik container
// (which carries CLF or JSON depending on configuration); falls back to
// container logs the same way GetTraefikLogs does today.
func readTraefikLogs(input traefikLogReadInput) (string, error) {
	logPath := ""
	if input.Database != nil {
		settings, _ := input.Database.GetSettings()
		logPath = settings.TraefikAccessLog
	}
	if logPath == "" {
		logPath = input.Config.TraefikAccessLog
	}
	if logPath != "" {
		if logs, err := input.Reader.ExecCommand(input.Config.TraefikContainerName, []string{"tail", "-n", input.Tail, logPath}); err == nil {
			return logs, nil
		} else {
			logger.Debug("traefik access log file unreadable; falling back to container logs", "error", err)
		}
	}
	return input.Reader.GetContainerLogs(input.Config.TraefikContainerName, input.Tail)
}
