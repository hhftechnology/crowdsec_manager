package middleware

import (
	"net/http"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

const dockerClientKey = "dockerClient"

// DockerHostSelector is Gin middleware that resolves the ?host= query param
// (or X-Docker-Host header) to the appropriate *docker.Client and stores it
// in the request context. If no host is specified, the default client is used.
func DockerHostSelector(multiHost *docker.MultiHostClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		hostID := c.Query("host")
		if hostID == "" {
			hostID = c.GetHeader("X-Docker-Host")
		}

		client, err := multiHost.GetClient(hostID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid docker host: " + err.Error(),
			})
			return
		}

		c.Set(dockerClientKey, client)
		c.Next()
	}
}

// GetDockerClient retrieves the per-request Docker client from the Gin context.
// Falls back to the provided default client if middleware hasn't run.
func GetDockerClient(c *gin.Context, fallback *docker.Client) *docker.Client {
	if val, exists := c.Get(dockerClientKey); exists {
		if client, ok := val.(*docker.Client); ok {
			return client
		}
	}
	return fallback
}
