package handlers

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// ImportDecisions imports decisions from a CSV file
func ImportDecisions(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "No file uploaded: " + err.Error(),
			})
			return
		}
		defer file.Close()

		if !strings.HasSuffix(strings.ToLower(header.Filename), ".csv") {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "File must be a CSV",
			})
			return
		}

		// Create a temp file to store the upload
		tempDir := os.TempDir()
		tempFilePath := filepath.Join(tempDir, fmt.Sprintf("decisions_import_%s", header.Filename))
		out, err := os.Create(tempFilePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to create temp file: " + err.Error(),
			})
			return
		}
		defer out.Close()
		defer os.Remove(tempFilePath) // Clean up after we're done

		// Copy file content to temp file
		if _, err := io.Copy(out, file); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to save uploaded file: " + err.Error(),
			})
			return
		}

		// Validate CSV content
		f, err := os.Open(tempFilePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to open temp file for validation: " + err.Error(),
			})
			return
		}
		defer f.Close()

		reader := csv.NewReader(f)
		records, err := reader.ReadAll()
		if err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Failed to parse CSV: " + err.Error(),
			})
			return
		}

		if len(records) == 0 {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "CSV file is empty",
			})
			return
		}

		// Validate headers
		headers := records[0]
		validHeaders := map[string]bool{
			"duration": true, "reason": true, "scope": true, "type": true, "value": true,
		}
		for _, h := range headers {
			if !validHeaders[strings.ToLower(h)] {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Invalid header: %s. Expected one of: duration, reason, scope, type, value", h),
				})
				return
			}
		}

		// Validate row count (limit to 100 IPs + 1 header)
		if len(records) > 101 {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "CSV contains too many rows. Limit is 100 decisions.",
			})
			return
		}

		// Write to container
		containerFile := "/tmp/decisions_import.csv"

		content, err := os.ReadFile(tempFilePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to read temp file: " + err.Error(),
			})
			return
		}

		err = dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, containerFile, content)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to copy file to container: " + err.Error(),
			})
			return
		}

		// Run import
		importCmd := []string{"cscli", "decisions", "import", "-i", containerFile}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, importCmd)

		// Cleanup container file
		dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"rm", containerFile})

		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to import decisions: %v. Output: %s", err, output),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Decisions imported successfully",
			Data:    gin.H{"output": output},
		})
	}
}
