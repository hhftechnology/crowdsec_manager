package diagnostics

import (
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"

	"crowdsec-manager/internal/config"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes adds opt-in runtime diagnostics for memory stability checks.
func RegisterRoutes(router *gin.RouterGroup, cfg *config.Config) {
	debug := router.Group("/debug", requireProfiling(cfg))

	debug.GET("/runtime", runtimeStats)
	debug.GET("/pprof/", gin.WrapF(pprof.Index))
	debug.GET("/pprof/cmdline", gin.WrapF(pprof.Cmdline))
	debug.GET("/pprof/profile", gin.WrapF(pprof.Profile))
	debug.POST("/pprof/symbol", gin.WrapF(pprof.Symbol))
	debug.GET("/pprof/symbol", gin.WrapF(pprof.Symbol))
	debug.GET("/pprof/trace", gin.WrapF(pprof.Trace))
	debug.GET("/pprof/:profile", profileHandler)
}

func requireProfiling(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg == nil || !cfg.EnableProfiling {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		if !cfg.ProfilingAllowRemote && !isLocalRequest(c.Request) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "profiling requires local access"})
			return
		}
		c.Next()
	}
}

func isLocalRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runtimeStats(c *gin.Context) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	c.JSON(http.StatusOK, gin.H{
		"goroutines":          runtime.NumGoroutine(),
		"heap_alloc_bytes":    mem.HeapAlloc,
		"heap_inuse_bytes":    mem.HeapInuse,
		"heap_idle_bytes":     mem.HeapIdle,
		"heap_released_bytes": mem.HeapReleased,
		"stack_inuse_bytes":   mem.StackInuse,
		"system_bytes":        mem.Sys,
		"total_alloc_bytes":   mem.TotalAlloc,
		"gc_cycles":           mem.NumGC,
		"last_gc_unix_nano":   mem.LastGC,
		"next_gc_bytes":       mem.NextGC,
		"gc_cpu_fraction":     mem.GCCPUFraction,
	})
}

func profileHandler(c *gin.Context) {
	pprof.Handler(c.Param("profile")).ServeHTTP(c.Writer, c.Request)
}
