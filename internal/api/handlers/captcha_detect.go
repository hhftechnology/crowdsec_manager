package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"crowdsec-manager/internal/compose"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// DetectCaptchaConfig scans all sources for existing captcha configuration and returns
// a FeatureDetectionResult describing what was found without modifying anything.
func DetectCaptchaConfig(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		detected := map[string]interface{}{}
		sources := map[string]bool{
			"traefik_dynamic_config": false,
			"docker_compose":         false,
			"database":               false,
			"html_file":              false,
		}

		// 1. Scan Traefik dynamic_config.yml for captcha keys.
		traefikValues := detectCaptchaInTraefikConfig(dockerClient, cfg)
		if len(traefikValues) > 0 {
			sources["traefik_dynamic_config"] = true
			for k, v := range traefikValues {
				detected[k] = v
			}
		}

		// 2. Scan docker-compose files for captcha-related env vars.
		captchaEnvKeys := []string{
			"TRAEFIK_CAPTCHA_HTML_PATH",
			"CAPTCHA_GRACE_PERIOD",
		}
		composeFiles := findComposeFiles(cfg)
		composeResult, err := compose.ScanMultipleComposeFiles(composeFiles, nil, captchaEnvKeys)
		if err == nil && composeResult.Found {
			sources["docker_compose"] = true
			for k, v := range composeResult.Values {
				detected["compose_"+strings.ToLower(k)] = v
			}
		}

		// 3. Check DB for a saved feature config.
		var dbConfig *models.FeatureConfig
		if db != nil {
			dbConfig, _ = db.GetFeatureConfig("captcha")
			if dbConfig != nil {
				sources["database"] = true
				// Merge stored values into detected (DB values do not override live-detected values).
				var stored map[string]interface{}
				if json.Unmarshal([]byte(dbConfig.ConfigJSON), &stored) == nil {
					for k, v := range stored {
						if _, exists := detected[k]; !exists {
							detected[k] = v
						}
					}
				}
			}
		}

		// 4. Check whether captcha.html exists on the host filesystem.
		htmlPath := filepath.Join(cfg.ConfigDir, "traefik", "conf", "captcha.html")
		if _, err := os.Stat(htmlPath); err == nil {
			sources["html_file"] = true
			detected["html_exists"] = true
			detected["html_path"] = htmlPath
		} else {
			detected["html_exists"] = false
			detected["html_path"] = htmlPath
		}

		// Determine overall status.
		status := "not_configured"
		switch {
		case sources["database"] && dbConfig != nil && dbConfig.Applied:
			status = "applied"
		case sources["traefik_dynamic_config"] && sources["html_file"]:
			status = "configured"
		case sources["traefik_dynamic_config"] || sources["database"]:
			status = "partially_configured"
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: models.FeatureDetectionResult{
				DetectedValues: detected,
				Sources:        sources,
				DBConfig:       dbConfig,
				Status:         status,
			},
		})
	}
}

// detectCaptchaInTraefikConfig reads Traefik dynamic config and extracts captcha-related values.
// It first attempts to read from the running container; on failure it falls back to the local file.
func detectCaptchaInTraefikConfig(dockerClient *docker.Client, cfg *config.Config) map[string]interface{} {
	result := map[string]interface{}{}

	output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{"cat", cfg.TraefikDynamicConfig})
	if err != nil {
		localPath := filepath.Join(cfg.ConfigDir, "traefik", "dynamic_config.yml")
		data, readErr := os.ReadFile(localPath)
		if readErr != nil {
			logger.Debug("Could not read Traefik dynamic config", "containerErr", err, "localErr", readErr)
			return result
		}
		output = string(data)
	}

	lower := strings.ToLower(output)
	if !strings.Contains(lower, "captchaprovider") && !strings.Contains(lower, "captchasitekey") {
		return result
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lowerLine := strings.ToLower(trimmed)

		if strings.Contains(lowerLine, "captchaprovider") {
			if val := extractYAMLValue(trimmed); val != "" {
				result["provider"] = val
			}
		}
		if strings.Contains(lowerLine, "captchasitekey") {
			if val := extractYAMLValue(trimmed); val != "" {
				result["site_key"] = val
			}
		}
		if strings.Contains(lowerLine, "captchasecretkey") {
			if val := extractYAMLValue(trimmed); val != "" {
				result["secret_key"] = val
			}
		}
	}

	return result
}

// extractYAMLValue extracts the value portion from a "key: value" YAML line.
func extractYAMLValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	val := strings.TrimSpace(parts[1])
	return strings.Trim(val, "\"'")
}

// findComposeFiles returns the list of compose file paths to scan, based on config.
// The primary ComposeFile is always first; additional candidates from PangolinDir are appended
// without duplicates (compared by absolute path).
func findComposeFiles(cfg *config.Config) []string {
	files := []string{}

	if cfg.ComposeFile != "" {
		files = append(files, cfg.ComposeFile)
	}

	candidates := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"docker-compose.pangolin.yml",
		"docker-compose.dev.yml",
	}

	for _, p := range candidates {
		candidate := filepath.Join(cfg.PangolinDir, p)
		if isDuplicatePath(files, candidate) {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			files = append(files, candidate)
		}
	}

	return files
}

// isDuplicatePath reports whether candidate (by absolute path) is already in the list.
func isDuplicatePath(existing []string, candidate string) bool {
	abs2, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	for _, e := range existing {
		abs1, err := filepath.Abs(e)
		if err != nil {
			continue
		}
		if abs1 == abs2 {
			return true
		}
	}
	return false
}
