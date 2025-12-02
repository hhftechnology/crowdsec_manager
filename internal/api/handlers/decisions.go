package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// AddDecisionRequest represents the payload for adding a decision
type AddDecisionRequest struct {
	IP       string `json:"ip"`
	Range    string `json:"range"`
	Duration string `json:"duration"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Reason   string `json:"reason"`
}

// AddDecision adds a new decision via cscli
func AddDecision(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req AddDecisionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request body: " + err.Error(),
			})
			return
		}

		cmd := []string{"cscli", "decisions", "add"}

		// Helper to add flag if value is present
		addFlag := func(flag, value string) {
			if value != "" {
				cmd = append(cmd, flag, value)
			}
		}

		addFlag("--ip", req.IP)
		addFlag("--range", req.Range)
		addFlag("--duration", req.Duration)
		addFlag("--type", req.Type)
		addFlag("--scope", req.Scope)
		addFlag("--value", req.Value)
		addFlag("--reason", req.Reason)

		logger.Info("Adding decision", "command", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to add decision", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to add decision: %v. Output: %s", err, output),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Decision added successfully",
			Data:    gin.H{"output": output},
		})
	}
}

// DeleteDecision deletes a decision via cscli
func DeleteDecision(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// We can accept query params or JSON body. Let's support both by binding query first then JSON if needed.
		// Actually, for DELETE, query params are standard, but sometimes bodies are used.
		// Let's stick to query params for simplicity as per the plan, but check if we need body support.
		// The plan said "Parse query params or JSON body". Let's try binding query.

		type DeleteDecisionRequest struct {
			ID       string `form:"id" json:"id"`
			IP       string `form:"ip" json:"ip"`
			Range    string `form:"range" json:"range"`
			Type     string `form:"type" json:"type"`
			Scope    string `form:"scope" json:"scope"`
			Value    string `form:"value" json:"value"`
			Scenario string `form:"scenario" json:"scenario"`
			Origin   string `form:"origin" json:"origin"`
		}

		var req DeleteDecisionRequest
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request parameters: " + err.Error(),
			})
			return
		}

		cmd := []string{"cscli", "decisions", "delete"}
		hasFilter := false

		addFlag := func(flag, value string) {
			if value != "" {
				cmd = append(cmd, flag, value)
				hasFilter = true
			}
		}

		addFlag("--id", req.ID)
		addFlag("--ip", req.IP)
		addFlag("--range", req.Range)
		addFlag("--type", req.Type)
		addFlag("--scope", req.Scope)
		addFlag("--value", req.Value)
		addFlag("--scenario", req.Scenario)
		addFlag("--origin", req.Origin)

		if !hasFilter {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "At least one filter (id, ip, range, etc.) must be provided to delete decisions",
			})
			return
		}

		logger.Info("Deleting decision", "command", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to delete decision", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete decision: %v. Output: %s", err, output),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Decision(s) deleted successfully",
			Data:    gin.H{"output": output},
		})
	}
}

// ImportDecisions imports decisions from a CSV file
func ImportDecisions(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
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
		// Re-open the file for reading
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

		// Now copy the temp file to the container or mount it?
		// Since we can't easily mount a new file to a running container without restarting,
		// we should copy the file into the container using `docker cp`.
		// However, our dockerClient might not have a direct `CopyToContainer` method exposed easily in the wrapper.
		// Let's check `docker.Client`. If not, we might need to use `cat` and pipe.
		// Or we can just read the file content and pass it via stdin if `cscli import` supported it, but it takes a file path.
		// A workaround is to write the file to a known shared volume if one exists, or use `docker exec -i ...` to write the file.
		// Let's try writing to `/tmp/decisions.csv` inside the container using `sh -c 'cat > ...'`.


		
		// Write to container
		containerFile := "/tmp/decisions_import.csv"
		
		// We need a way to pass input to ExecCommand. The current `ExecCommand` helper might not support stdin.
		// Let's check `internal/docker/client.go`.
		
		// If `ExecCommand` doesn't support stdin, we might need to extend it or use a different approach.
		// Assuming for now we need to check `docker.Client`.
		
		// Alternative: If we can't easily write to the container, we can parse the CSV and run `cscli decisions add` for each row.
		// But that might be slow and not atomic.
		// The user request specifically mentioned `cscli decisions import`.
		
		// Let's assume for a moment we can't easily write to the container with the current `ExecCommand`.
		// I'll check `internal/docker/client.go` in the next step.
		// For now, I'll implement the logic assuming I can figure out the file transfer.
		// Actually, I'll pause the implementation of the *transfer* part and just put a placeholder or check the docker client first.
		
		// Wait, I can't check the file in the middle of writing this file.
		// I will write the file with a TODO or a best-effort approach.
		// Best effort: Use `docker cp` via shell command on the host if the app is running on the host and has docker access.
		// But the app is running in a container usually? No, the user environment says `g:\github\crowdsec_manager`.
		// The app is likely running on the host (Windows) or in a dev container.
		// The `dockerClient` wraps the Docker API.
		
		// Let's use the `docker cp` command structure if possible, but `dockerClient` is a wrapper.
		// I'll assume I can use `ExecCommand` to write the file if I escape it correctly, but that's risky with CSV content.
		
		// BETTER APPROACH:
		// Since I am writing this file now, I will assume I can update `docker/client.go` to support `CopyToContainer` or similar if needed.
		// For now, I will use a placeholder for the copy operation and finish the rest of the logic.
		
		// Actually, let's look at `ExecCommand` usage. It takes `cmd []string`.
		// I'll use a simple loop to add decisions one by one if import is too hard, BUT the user explicitly asked for `import`.
		
		// Let's try to use `docker exec` with `echo` to write the file line by line? No, too slow/complex.
		
		// I will stick to the plan: `ImportDecisions` handles `cscli decisions import`.
		// I will implement a helper `copyFileToContainer` in `decisions.go` for now that uses `docker cp` via `exec.Command` on the host?
		// No, `dockerClient` should handle it.
		
		// Let's just write the code assuming `dockerClient.CopyToContainer` exists or I'll add it.
		// I'll check `docker/client.go` right after this.
		
		// For this file, I'll implement the handler to call a helper function `copyToContainer`.
		
		err = copyToContainer(dockerClient, cfg.CrowdsecContainerName, tempFilePath, containerFile)
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

// copyToContainer is a helper to copy a file to the container
func copyToContainer(client *docker.Client, containerName, srcPath, dstPath string) error {
	// Open the source file
	f, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer f.Close()

	// Use the client's CopyToContainer method which takes an io.Reader
	return client.CopyToContainer(containerName, dstPath, f)
}
