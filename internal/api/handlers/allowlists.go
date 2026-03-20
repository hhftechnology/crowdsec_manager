package handlers

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

// =============================================================================
// ALLOWLIST MANAGEMENT
// =============================================================================

// ListAllowlists lists all CrowdSec allowlists
func ListAllowlists(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Listing allowlists")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "allowlists", "list", "-o", "json"})
		if err != nil {
			logger.Error("Failed to list allowlists", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list allowlists: %v", err),
			})
			return
		}

		// Check if output is empty or null
		if output == "null" || output == "" || output == "[]" {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    gin.H{"allowlists": []models.Allowlist{}, "count": 0},
				Message: "No allowlists found",
			})
			return
		}

		// Parse allowlists using normalized CLI JSON output.
		var allowlists []models.Allowlist
		dataBytes, parseErr := parseCLIJSONToBytes(output)
		if parseErr != nil {
			logger.Error("Failed to normalize allowlists JSON", "error", parseErr, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse allowlists: %v", parseErr),
			})
			return
		}

		_, err = jsonparser.ArrayEach(dataBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			var allowlist models.Allowlist

			// Extract fields
			if name, err := jsonparser.GetString(value, "name"); err == nil {
				allowlist.Name = name
			}
			if desc, err := jsonparser.GetString(value, "description"); err == nil {
				allowlist.Description = desc
			}
			if createdAt, err := jsonparser.GetString(value, "created_at"); err == nil {
				allowlist.CreatedAt = createdAt
			}
			if updatedAt, err := jsonparser.GetString(value, "updated_at"); err == nil {
				allowlist.UpdatedAt = updatedAt
			}

			// Parse items array
			var items []models.AllowlistEntry
			jsonparser.ArrayEach(value, func(itemValue []byte, itemType jsonparser.ValueType, itemOffset int, itemErr error) {
				var entry models.AllowlistEntry

				if val, err := jsonparser.GetString(itemValue, "value"); err == nil {
					entry.Value = val
				}
				if exp, err := jsonparser.GetString(itemValue, "expiration"); err == nil {
					entry.Expiration = exp
				}
				if createdAt, err := jsonparser.GetString(itemValue, "created_at"); err == nil {
					// Parse time
					if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
						entry.CreatedAt = t
					}
				}

				items = append(items, entry)
			}, "items")

			allowlist.Items = items
			allowlist.Size = len(items)

			allowlists = append(allowlists, allowlist)
		})

		if err != nil {
			logger.Error("Failed to parse allowlists JSON", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse allowlists: %v", err),
			})
			return
		}

		logger.Debug("Allowlists retrieved successfully", "count", len(allowlists))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"allowlists": allowlists, "count": len(allowlists)},
			Message: fmt.Sprintf("Found %d allowlists", len(allowlists)),
		})
	}
}

// CreateAllowlist creates a new CrowdSec allowlist
func CreateAllowlist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.AllowlistCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Invalid request: %v", err),
			})
			return
		}

		logger.Info("Creating allowlist", "name", req.Name)

		cmd := []string{"cscli", "allowlists", "create", req.Name, "--description", req.Description}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to create allowlist", "name", req.Name, "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create allowlist: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: models.Allowlist{
				Name:        req.Name,
				Description: req.Description,
				CreatedAt:   time.Now().Format(time.RFC3339),
			},
			Message: fmt.Sprintf("Allowlist '%s' created successfully", req.Name),
		})
	}
}

// InspectAllowlist inspects a specific allowlist
func InspectAllowlist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		name := c.Param("name")
		logger.Info("Inspecting allowlist", "name", name)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "allowlists", "inspect", name, "-o", "json"})
		if err != nil {
			logger.Error("Failed to inspect allowlist", "name", name, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to inspect allowlist: %v", err),
			})
			return
		}

		// Parse response using normalized CLI JSON output.
		dataBytes, parseErr := parseCLIJSONToBytes(output)
		if parseErr != nil {
			logger.Error("Failed to normalize allowlist inspect JSON", "name", name, "error", parseErr)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse allowlist response: %v", parseErr),
			})
			return
		}
		var response models.AllowlistInspectResponse

		// Extract top-level fields
		if n, err := jsonparser.GetString(dataBytes, "name"); err == nil {
			response.Name = n
		}
		if desc, err := jsonparser.GetString(dataBytes, "description"); err == nil {
			response.Description = desc
		}
		if createdAt, err := jsonparser.GetString(dataBytes, "created_at"); err == nil {
			if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
				response.CreatedAt = t.Format(time.RFC3339)
			} else {
				response.CreatedAt = createdAt
			}
		}
		if updatedAt, err := jsonparser.GetString(dataBytes, "updated_at"); err == nil {
			if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
				response.UpdatedAt = t.Format(time.RFC3339)
			} else {
				response.UpdatedAt = updatedAt
			}
		}

		// Parse items array
		var items []models.AllowlistEntry
		jsonparser.ArrayEach(dataBytes, func(itemValue []byte, itemType jsonparser.ValueType, itemOffset int, itemErr error) {
			var entry models.AllowlistEntry

			if val, err := jsonparser.GetString(itemValue, "value"); err == nil {
				entry.Value = val
			}
			if exp, err := jsonparser.GetString(itemValue, "expiration"); err == nil {
				entry.Expiration = exp
			}
			if createdAt, err := jsonparser.GetString(itemValue, "created_at"); err == nil {
				if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
					entry.CreatedAt = t
				}
			}

			items = append(items, entry)
		}, "items")

		response.Items = items
		response.Count = len(items)

		logger.Debug("Allowlist inspected successfully", "name", name, "count", response.Count)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    response,
			Message: fmt.Sprintf("Allowlist '%s' has %d entries", name, response.Count),
		})
	}
}

// AddAllowlistEntries adds entries to an allowlist
func AddAllowlistEntries(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.AllowlistAddEntriesRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Invalid request: %v", err),
			})
			return
		}

		logger.Info("Adding entries to allowlist", "name", req.AllowlistName, "count", len(req.Values))

		// Build command
		cmd := []string{"cscli", "allowlists", "add", req.AllowlistName}
		cmd = append(cmd, req.Values...)

		// Add optional flags
		if req.Expiration != "" {
			cmd = append(cmd, "-e", req.Expiration)
		}
		if req.Description != "" {
			cmd = append(cmd, "-d", req.Description)
		}

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to add entries to allowlist", "name", req.AllowlistName, "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to add entries: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Added %d entries to allowlist '%s'", len(req.Values), req.AllowlistName),
		})
	}
}

// RemoveAllowlistEntries removes entries from an allowlist
func RemoveAllowlistEntries(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.AllowlistRemoveEntriesRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Invalid request: %v", err),
			})
			return
		}

		logger.Info("Removing entries from allowlist", "name", req.AllowlistName, "count", len(req.Values))

		cmd := []string{"cscli", "allowlists", "remove", req.AllowlistName}
		cmd = append(cmd, req.Values...)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to remove entries from allowlist", "name", req.AllowlistName, "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to remove entries: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Removed %d entries from allowlist '%s'", len(req.Values), req.AllowlistName),
		})
	}
}

// DeleteAllowlist deletes an allowlist
func DeleteAllowlist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		name := c.Param("name")
		logger.Info("Deleting allowlist", "name", name)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "allowlists", "delete", name})
		if err != nil {
			logger.Error("Failed to delete allowlist", "name", name, "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete allowlist: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Allowlist '%s' deleted successfully", name),
		})
	}
}

// =============================================================================
// ALLOWLIST IMPORT
// =============================================================================

// privateIPRanges holds RFC 1918, loopback, and link-local ranges used by isPrivateIPAddr.
var privateIPRanges = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	ranges := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil {
			ranges = append(ranges, ipNet)
		}
	}
	return ranges
}()

// isValidIPOrCIDR returns true if s is a valid IP address or CIDR notation.
func isValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// isPrivateIPAddr returns true if s falls within a private/loopback address range.
func isPrivateIPAddr(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		// For CIDRs, check the network address
		ip, _, _ = net.ParseCIDR(s)
	}
	if ip == nil {
		return false
	}
	for _, r := range privateIPRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// parseAllowlistImportFile reads a reader and returns unique, non-empty candidate strings.
// Entries can be separated by newlines or commas.
func parseAllowlistImportFile(r io.Reader) []string {
	seen := make(map[string]struct{})
	var out []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, part := range strings.Split(line, ",") {
			entry := strings.TrimSpace(part)
			if entry == "" {
				continue
			}
			if _, exists := seen[entry]; !exists {
				seen[entry] = struct{}{}
				out = append(out, entry)
			}
		}
	}
	return out
}

// getExistingAllowlistValues fetches the current values in an allowlist for duplicate detection.
func getExistingAllowlistValues(dockerClient *docker.Client, containerName, allowlistName string) map[string]struct{} {
	existing := make(map[string]struct{})
	output, err := dockerClient.ExecCommand(containerName, []string{"cscli", "allowlists", "inspect", allowlistName, "-o", "json"})
	if err != nil {
		return existing
	}
	dataBytes, err := parseCLIJSONToBytes(output)
	if err != nil {
		return existing
	}
	jsonparser.ArrayEach(dataBytes, func(itemValue []byte, _ jsonparser.ValueType, _ int, _ error) {
		if val, err := jsonparser.GetString(itemValue, "value"); err == nil {
			existing[val] = struct{}{}
		}
	}, "items")
	return existing
}

// ImportAllowlistEntries imports a plain-text list of IPs/CIDRs into an allowlist with optional filtering.
// Accepts multipart/form-data with fields:
//   - file             – text file, one IP/CIDR per line (or comma-separated)
//   - allowlist_name   – target allowlist (required)
//   - expiration       – optional, e.g. "7d", "30d"
//   - description      – optional note added to entries
//   - skip_invalid     – "true"/"false" (default true)  – drop non-IP/CIDR tokens
//   - skip_private     – "true"/"false" (default false) – drop RFC 1918 addresses
//   - skip_duplicates  – "true"/"false" (default true)  – drop entries already in allowlist
func ImportAllowlistEntries(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		allowlistName := strings.TrimSpace(c.PostForm("allowlist_name"))
		if allowlistName == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "allowlist_name is required",
			})
			return
		}

		expiration := strings.TrimSpace(c.PostForm("expiration"))
		description := strings.TrimSpace(c.PostForm("description"))

		parseBool := func(key string, defaultVal bool) bool {
			v := strings.TrimSpace(c.PostForm(key))
			if v == "" {
				return defaultVal
			}
			b, err := strconv.ParseBool(v)
			if err != nil {
				return defaultVal
			}
			return b
		}
		skipInvalid := parseBool("skip_invalid", true)
		skipPrivate := parseBool("skip_private", false)
		skipDuplicates := parseBool("skip_duplicates", true)

		file, _, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "file upload required: " + err.Error(),
			})
			return
		}
		defer file.Close()

		candidates := parseAllowlistImportFile(file)

		var (
			skippedInvalid    int
			skippedPrivate    int
			skippedDuplicates int
			toAdd             []string
		)

		var existing map[string]struct{}
		if skipDuplicates {
			existing = getExistingAllowlistValues(dockerClient, cfg.CrowdsecContainerName, allowlistName)
		}

		for _, entry := range candidates {
			if skipInvalid && !isValidIPOrCIDR(entry) {
				skippedInvalid++
				continue
			}
			if skipPrivate && isPrivateIPAddr(entry) {
				skippedPrivate++
				continue
			}
			if skipDuplicates {
				if _, exists := existing[entry]; exists {
					skippedDuplicates++
					continue
				}
			}
			toAdd = append(toAdd, entry)
		}

		imported := 0
		const chunkSize = 50
		for i := 0; i < len(toAdd); i += chunkSize {
			end := i + chunkSize
			if end > len(toAdd) {
				end = len(toAdd)
			}
			chunk := toAdd[i:end]

			cmd := []string{"cscli", "allowlists", "add", allowlistName}
			if expiration != "" {
				cmd = append(cmd, "--expiration", expiration)
			}
			if description != "" {
				cmd = append(cmd, "--description", description)
			}
			cmd = append(cmd, chunk...)

			output, execErr := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
			if execErr != nil {
				logger.Error("Failed to add allowlist chunk", "name", allowlistName, "error", execErr, "output", output)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to add entries (imported %d so far): %v", imported, execErr),
				})
				return
			}
			imported += len(chunk)
		}

		logger.Info("Allowlist import completed",
			"name", allowlistName,
			"total_input", len(candidates),
			"imported", imported,
			"skipped_invalid", skippedInvalid,
			"skipped_private", skippedPrivate,
			"skipped_duplicates", skippedDuplicates,
		)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Imported %d entries into '%s'", imported, allowlistName),
			Data: gin.H{
				"total_input":        len(candidates),
				"imported":           imported,
				"skipped_invalid":    skippedInvalid,
				"skipped_private":    skippedPrivate,
				"skipped_duplicates": skippedDuplicates,
			},
		})
	}
}
