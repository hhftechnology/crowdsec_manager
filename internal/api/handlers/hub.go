package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

type hubCategorySpec struct {
	Key            string `json:"key"`
	Label          string `json:"label"`
	CLIType        string `json:"cli_type"`
	ContainerDir   string `json:"container_dir"`
	SupportsDirect bool   `json:"supports_direct"`
}

var hubCategorySpecs = map[string]hubCategorySpec{
	"collections": {
		Key:            "collections",
		Label:          "Collections",
		CLIType:        "collections",
		ContainerDir:   "/etc/crowdsec/collections",
		SupportsDirect: true,
	},
	"scenarios": {
		Key:            "scenarios",
		Label:          "Attack scenarios",
		CLIType:        "scenarios",
		ContainerDir:   "/etc/crowdsec/scenarios",
		SupportsDirect: true,
	},
	"parsers": {
		Key:            "parsers",
		Label:          "Log parsers",
		CLIType:        "parsers",
		ContainerDir:   "/etc/crowdsec/parsers",
		SupportsDirect: true,
	},
	"postoverflows": {
		Key:            "postoverflows",
		Label:          "Postoverflows",
		CLIType:        "postoverflows",
		ContainerDir:   "/etc/crowdsec/postoverflows",
		SupportsDirect: true,
	},
	"remediations": {
		Key:            "remediations",
		Label:          "Remediation components",
		CLIType:        "collections",
		ContainerDir:   "/etc/crowdsec/collections",
		SupportsDirect: true,
	},
	"appsec-configs": {
		Key:            "appsec-configs",
		Label:          "AppSec configurations",
		CLIType:        "appsec-configs",
		ContainerDir:   "/etc/crowdsec/appsec-configs",
		SupportsDirect: true,
	},
	"appsec-rules": {
		Key:            "appsec-rules",
		Label:          "AppSec rules",
		CLIType:        "appsec-rules",
		ContainerDir:   "/etc/crowdsec/appsec-rules",
		SupportsDirect: true,
	},
}

var hubCategoryOrder = []string{
	"collections",
	"scenarios",
	"parsers",
	"postoverflows",
	"remediations",
	"appsec-configs",
	"appsec-rules",
}

func getHubCategorySpec(category string) (hubCategorySpec, bool) {
	spec, ok := hubCategorySpecs[strings.TrimSpace(strings.ToLower(category))]
	return spec, ok
}

func isValidHubMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "direct", "manual":
		return true
	default:
		return false
	}
}

// validateHubItemName checks that the hub item name looks reasonable
// (author/name format, no shell metacharacters).
func validateHubItemName(name string) bool {
	if name == "" {
		return false
	}
	for _, ch := range name {
		if ch == ';' || ch == '&' || ch == '|' || ch == '$' || ch == '`' ||
			ch == '(' || ch == ')' || ch == '{' || ch == '}' || ch == '<' ||
			ch == '>' || ch == '\'' || ch == '"' || ch == '\\' || ch == '\n' ||
			ch == '\r' || ch == ' ' || ch == '\t' {
			return false
		}
	}
	return true
}

func sanitizeHubFilename(name string) (string, error) {
	clean := path.Base(strings.TrimSpace(name))
	if clean == "." || clean == "" {
		return "", fmt.Errorf("filename is required")
	}
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("invalid filename")
	}
	if !strings.HasSuffix(clean, ".yaml") && !strings.HasSuffix(clean, ".yml") {
		return "", fmt.Errorf("filename must end with .yaml or .yml")
	}
	return clean, nil
}

func defaultHubApplyCommand(spec hubCategorySpec) []string {
	switch spec.Key {
	case "parsers", "postoverflows":
		return []string{"cscli", "parsers", "reload"}
	case "scenarios", "collections", "remediations", "appsec-configs", "appsec-rules":
		return []string{"kill", "-SIGHUP", "1"}
	default:
		return nil
	}
}

func executeHubApplyCommand(dockerClient *docker.Client, containerName string, spec hubCategorySpec) (string, string, error) {
	cmd := defaultHubApplyCommand(spec)
	if len(cmd) == 0 {
		return "", "", nil
	}

	output, err := dockerClient.ExecCommand(containerName, cmd)
	if err == nil {
		return strings.Join(cmd, " "), output, nil
	}

	// Reload signals can fail on some images; fallback to restart where appropriate.
	if len(cmd) >= 3 && cmd[0] == "kill" && cmd[1] == "-SIGHUP" && cmd[2] == "1" {
		if restartErr := dockerClient.RestartContainerWithTimeout(containerName, 30); restartErr != nil {
			return strings.Join(cmd, " "), output, fmt.Errorf("reload failed: %v, restart fallback failed: %w", err, restartErr)
		}
		return "docker-restart-fallback", output, nil
	}

	return strings.Join(cmd, " "), output, err
}

func persistHubOperation(db *database.Database, record models.HubOperationRecord) {
	if err := db.CreateHubOperation(&record); err != nil {
		logger.Warn("Failed to persist hub operation", "error", err)
	}
}

func upsertHubPreference(db *database.Database, category, mode, defaultPath, lastItem string) {
	pref, err := db.GetHubPreference(category)
	if err != nil {
		logger.Warn("Failed reading hub preference", "category", category, "error", err)
		pref = &models.HubPreference{Category: category, DefaultMode: "direct"}
	}
	if mode != "" {
		pref.DefaultMode = mode
	}
	if defaultPath != "" {
		pref.DefaultYAMLPath = defaultPath
	}
	if lastItem != "" {
		pref.LastItemName = lastItem
	}
	if pref.DefaultMode == "" {
		pref.DefaultMode = "direct"
	}
	if err := db.UpsertHubPreference(pref); err != nil {
		logger.Warn("Failed updating hub preference", "category", category, "error", err)
	}
}

// ListHubCategories returns the supported category metadata.
func ListHubCategories() gin.HandlerFunc {
	return func(c *gin.Context) {
		categories := make([]hubCategorySpec, 0, len(hubCategoryOrder))
		for _, key := range hubCategoryOrder {
			categories = append(categories, hubCategorySpecs[key])
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Data: categories})
	}
}

// ListHubItems returns legacy hub list output for the browser overview page.
func ListHubItems(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		cmd := []string{"cscli", "hub", "list", "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list hub items: %v", err),
			})
			return
		}

		var parsed interface{}
		if err := json.Unmarshal([]byte(output), &parsed); err != nil {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    output,
				Message: "Hub items retrieved (raw format)",
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    parsed,
			Message: "Hub items retrieved successfully",
		})
	}
}

// ListHubItemsByCategory lists category items using cscli.
func ListHubItemsByCategory(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		spec, ok := getHubCategorySpec(c.Param("category"))
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid hub category"})
			return
		}

		cmd := []string{"cscli", spec.CLIType, "list", "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("Failed to list %s: %v", spec.Key, err)})
			return
		}

		var parsed interface{}
		if err := json.Unmarshal([]byte(output), &parsed); err != nil {
			c.JSON(http.StatusOK, models.Response{Success: true, Data: gin.H{"category": spec, "raw_output": output}})
			return
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Data: gin.H{"category": spec, "items": parsed}})
	}
}

// InstallHubItemByCategory installs a hub item from structured input.
func InstallHubItemByCategory(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		spec, ok := getHubCategorySpec(c.Param("category"))
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid hub category"})
			return
		}

		var req models.HubCategoryActionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid request: " + err.Error()})
			return
		}
		req.ItemName = strings.TrimSpace(req.ItemName)
		if !validateHubItemName(req.ItemName) {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid item name"})
			return
		}

		cmd := []string{"cscli", spec.CLIType, "install", req.ItemName, "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		record := models.HubOperationRecord{
			Category: spec.Key,
			Mode:     "direct",
			Action:   "install",
			ItemName: req.ItemName,
			Command:  strings.Join(cmd, " "),
			Output:   output,
			Success:  err == nil,
		}
		if err != nil {
			record.Error = err.Error()
			persistHubOperation(db, record)
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("Failed to install %s: %v", req.ItemName, err)})
			return
		}

		persistHubOperation(db, record)
		upsertHubPreference(db, spec.Key, "direct", "", req.ItemName)

		c.JSON(http.StatusOK, models.Response{Success: true, Message: fmt.Sprintf("Installed %s", req.ItemName), Data: gin.H{"output": output}})
	}
}

// RemoveHubItemByCategory removes a hub item from structured input.
func RemoveHubItemByCategory(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		spec, ok := getHubCategorySpec(c.Param("category"))
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid hub category"})
			return
		}

		var req models.HubCategoryActionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid request: " + err.Error()})
			return
		}
		req.ItemName = strings.TrimSpace(req.ItemName)
		if !validateHubItemName(req.ItemName) {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid item name"})
			return
		}

		cmd := []string{"cscli", spec.CLIType, "remove", req.ItemName, "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		record := models.HubOperationRecord{
			Category: spec.Key,
			Mode:     "direct",
			Action:   "remove",
			ItemName: req.ItemName,
			Command:  strings.Join(cmd, " "),
			Output:   output,
			Success:  err == nil,
		}
		if err != nil {
			record.Error = err.Error()
			persistHubOperation(db, record)
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("Failed to remove %s: %v", req.ItemName, err)})
			return
		}

		persistHubOperation(db, record)
		upsertHubPreference(db, spec.Key, "direct", "", req.ItemName)

		c.JSON(http.StatusOK, models.Response{Success: true, Message: fmt.Sprintf("Removed %s", req.ItemName), Data: gin.H{"output": output}})
	}
}

// ManualApplyHubYAML writes YAML to the category directory and applies when supported.
func ManualApplyHubYAML(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		spec, ok := getHubCategorySpec(c.Param("category"))
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid hub category"})
			return
		}

		var req models.HubManualApplyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid request: " + err.Error()})
			return
		}

		filename, err := sanitizeHubFilename(req.Filename)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: err.Error()})
			return
		}
		req.YAML = strings.TrimSpace(req.YAML)
		if req.YAML == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "yaml is required"})
			return
		}

		var tmp interface{}
		if err := yaml.Unmarshal([]byte(req.YAML), &tmp); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: fmt.Sprintf("invalid yaml: %v", err)})
			return
		}

		targetPath := strings.TrimSpace(req.TargetPath)
		if targetPath == "" {
			targetPath = path.Join(spec.ContainerDir, filename)
		} else {
			targetPath = path.Clean(targetPath)
			if !strings.HasPrefix(targetPath, spec.ContainerDir+"/") {
				c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "target_path must stay inside category directory"})
				return
			}
		}

		if err := dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, targetPath, []byte(req.YAML)); err != nil {
			record := models.HubOperationRecord{
				Category:    spec.Key,
				Mode:        "manual",
				Action:      "manual_apply",
				ItemName:    filename,
				YAMLPath:    targetPath,
				YAMLContent: req.YAML,
				Success:     false,
				Error:       err.Error(),
			}
			persistHubOperation(db, record)
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to write file: %v", err)})
			return
		}

		appliedCommand, applyOutput, applyErr := executeHubApplyCommand(dockerClient, cfg.CrowdsecContainerName, spec)
		if applyErr != nil {
			record := models.HubOperationRecord{
				Category:    spec.Key,
				Mode:        "manual",
				Action:      "manual_apply",
				ItemName:    filename,
				YAMLPath:    targetPath,
				YAMLContent: req.YAML,
				Command:     appliedCommand,
				Output:      applyOutput,
				Success:     false,
				Error:       applyErr.Error(),
			}
			persistHubOperation(db, record)
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("yaml written but apply failed: %v", applyErr)})
			return
		}

		record := models.HubOperationRecord{
			Category:    spec.Key,
			Mode:        "manual",
			Action:      "manual_apply",
			ItemName:    filename,
			YAMLPath:    targetPath,
			YAMLContent: req.YAML,
			Success:     true,
			Output:      applyOutput,
		}
		if appliedCommand != "" {
			record.Command = appliedCommand
		}
		persistHubOperation(db, record)
		upsertHubPreference(db, spec.Key, "manual", targetPath, filename)

		message := "YAML applied successfully"
		if appliedCommand == "" {
			message = "YAML written successfully (no apply command for this category)"
		}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: message,
			Data: gin.H{
				"path":            targetPath,
				"apply_output":    applyOutput,
				"applied_command": appliedCommand,
			},
		})
	}
}

// GetHubPreferences returns all preferences.
func GetHubPreferences(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		prefs, err := db.ListHubPreferences()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to load preferences: %v", err)})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Data: prefs})
	}
}

// GetHubPreferenceByCategory returns a preference row by category.
func GetHubPreferenceByCategory(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		category := strings.ToLower(strings.TrimSpace(c.Param("category")))
		if _, ok := getHubCategorySpec(category); !ok {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid hub category"})
			return
		}
		pref, err := db.GetHubPreference(category)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to load preference: %v", err)})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Data: pref})
	}
}

// UpdateHubPreference updates category preference defaults.
func UpdateHubPreference(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		category := strings.ToLower(strings.TrimSpace(c.Param("category")))
		spec, ok := getHubCategorySpec(category)
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid hub category"})
			return
		}

		var req models.HubPreference
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid request: " + err.Error()})
			return
		}

		req.Category = spec.Key
		req.DefaultMode = strings.ToLower(strings.TrimSpace(req.DefaultMode))
		if req.DefaultMode == "" {
			req.DefaultMode = "direct"
		}
		if !isValidHubMode(req.DefaultMode) {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "default_mode must be one of: direct, manual"})
			return
		}
		if req.DefaultYAMLPath != "" {
			clean := path.Clean(req.DefaultYAMLPath)
			if !strings.HasPrefix(clean, spec.ContainerDir+"/") {
				c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "default_yaml_path must stay inside category directory"})
				return
			}
			req.DefaultYAMLPath = clean
		}

		if err := db.UpsertHubPreference(&req); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to save preference: %v", err)})
			return
		}

		pref, _ := db.GetHubPreference(spec.Key)
		c.JSON(http.StatusOK, models.Response{Success: true, Message: "Preference updated", Data: pref})
	}
}

// ListHubOperationHistory returns operation history with query filters.
func ListHubOperationHistory(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		filter := models.HubOperationFilter{
			Category: strings.ToLower(strings.TrimSpace(c.Query("category"))),
			Mode:     strings.ToLower(strings.TrimSpace(c.Query("mode"))),
			Limit:    50,
			Offset:   0,
		}

		if v := strings.TrimSpace(c.Query("limit")); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil {
				filter.Limit = parsed
			}
		}
		if v := strings.TrimSpace(c.Query("offset")); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil {
				filter.Offset = parsed
			}
		}
		if v := strings.TrimSpace(c.Query("success")); v != "" {
			if parsed, err := strconv.ParseBool(v); err == nil {
				filter.Success = &parsed
			}
		}

		records, err := db.ListHubOperations(filter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to load history: %v", err)})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Data: records})
	}
}

// GetHubOperationByID returns one operation entry by id.
func GetHubOperationByID(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid history id"})
			return
		}

		record, err := db.GetHubOperationByID(id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to load history item: %v", err)})
			return
		}
		if record == nil {
			c.JSON(http.StatusNotFound, models.Response{Success: false, Error: "History item not found"})
			return
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Data: record})
	}
}

// UpgradeAllHub upgrades all hub items and records the operation.
func UpgradeAllHub(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		cmd := []string{"cscli", "hub", "upgrade", "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		record := models.HubOperationRecord{
			Category: "hub",
			Mode:     "direct",
			Action:   "upgrade_all",
			Command:  strings.Join(cmd, " "),
			Output:   output,
			Success:  err == nil,
		}
		if err != nil {
			record.Error = err.Error()
			persistHubOperation(db, record)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to upgrade hub items: %v", err),
			})
			return
		}

		persistHubOperation(db, record)
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    output,
			Message: "Hub items upgraded successfully",
		})
	}
}
