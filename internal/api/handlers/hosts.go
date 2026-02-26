package handlers

import (
	"net/http"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// ListDockerHosts returns all configured Docker hosts with connectivity status
func ListDockerHosts(multiHost *docker.MultiHostClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		hosts := multiHost.ListHosts()

		type HostStatus struct {
			docker.HostInfo
			Connected bool   `json:"connected"`
			Error     string `json:"error,omitempty"`
			IsDefault bool   `json:"is_default"`
		}

		defaultID := multiHost.DefaultHostID()
		results := make([]HostStatus, 0, len(hosts))

		for _, h := range hosts {
			hs := HostStatus{
				HostInfo:  h,
				IsDefault: h.ID == defaultID,
			}

			client, err := multiHost.GetClient(h.ID)
			if err != nil {
				hs.Error = err.Error()
			} else if err := client.Ping(); err != nil {
				hs.Error = err.Error()
			} else {
				hs.Connected = true
			}

			results = append(results, hs)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    results,
		})
	}
}
