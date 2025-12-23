package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// PathConfig holds all configurable paths for the application
// Paths can be configured via:
// 1. User preferences (stored in database) - highest priority
// 2. Environment variables - medium priority
// 3. Sensible defaults - lowest priority
type PathConfig struct {
	// Traefik Paths (container-internal paths)
	TraefikDynamicConfig string // Path to dynamic_config.yml in Traefik container
	TraefikStaticConfig  string // Path to traefik.yml in Traefik container
	TraefikAccessLog     string // Path to access log in Traefik container
	TraefikErrorLog      string // Path to error log in Traefik container
	TraefikAssetsDir     string // Directory for assets (captcha, etc.) in Traefik container
	TraefikCaptchaHTML   string // Path to captcha.html in Traefik container
	TraefikRulesDir      string // Directory for dynamic rules in Traefik container
	TraefikConfDir       string // Directory for configuration files in Traefik container

	// CrowdSec Paths (container-internal paths)
	CrowdSecAcquisFile string // Path to acquis.yaml in CrowdSec container
	CrowdSecAcquisDir  string // Path to acquis.d directory in CrowdSec container
	CrowdSecConfigDir  string // Path to config directory in CrowdSec container
	CrowdSecDataDir    string // Path to data directory in CrowdSec container

	// Manager Paths (container-internal paths)
	ManagerConfigDir string // Path to config directory in Manager container
	ManagerDataDir   string // Path to data directory in Manager container
	ManagerBackupDir string // Path to backups directory in Manager container
	ManagerLogDir    string // Path to logs directory in Manager container

	// Multi-Proxy Support (container-internal paths)
	NginxConfigPath   string // Path to nginx config in NPM container
	NginxLogPath      string // Path to nginx logs in NPM container
	CaddyConfigPath   string // Path to Caddyfile in Caddy container
	CaddyLogPath      string // Path to Caddy logs in Caddy container
	HAProxyConfigPath string // Path to haproxy.cfg in HAProxy container
	HAProxySocketPath string // Path to HAProxy admin socket
	ZoraxyConfigPath  string // Path to Zoraxy config in Zoraxy container
}

// NewPathConfig creates a new PathConfig with default values
func NewPathConfig() *PathConfig {
	return &PathConfig{
		// Traefik defaults (standard Traefik container paths)
		TraefikDynamicConfig: "/etc/traefik/dynamic_config.yml",
		TraefikStaticConfig:  "/etc/traefik/traefik.yml",
		TraefikAccessLog:     "/var/log/traefik/access.log",
		TraefikErrorLog:      "/var/log/traefik/traefik.log",
		TraefikAssetsDir:     "/etc/traefik/assets",
		TraefikCaptchaHTML:   "/etc/traefik/assets/captcha.html",
		TraefikRulesDir:      "/etc/traefik/rules",
		TraefikConfDir:       "/etc/traefik/conf",

		// CrowdSec defaults (standard CrowdSec container paths)
		CrowdSecAcquisFile: "/etc/crowdsec/acquis.yaml",
		CrowdSecAcquisDir:  "/etc/crowdsec/acquis.d",
		CrowdSecConfigDir:  "/etc/crowdsec",
		CrowdSecDataDir:    "/var/lib/crowdsec/data",

		// Manager defaults (standard Manager container paths)
		ManagerConfigDir: "/app/config",
		ManagerDataDir:   "/app/data",
		ManagerBackupDir: "/app/backups",
		ManagerLogDir:    "/app/logs",

		// Multi-Proxy defaults
		NginxConfigPath:   "/data/nginx",
		NginxLogPath:      "/data/logs",
		CaddyConfigPath:   "/etc/caddy",
		CaddyLogPath:      "/var/log/caddy",
		HAProxyConfigPath: "/usr/local/etc/haproxy",
		HAProxySocketPath: "/var/run/haproxy.sock",
		ZoraxyConfigPath:  "/opt/zoraxy",
	}
}

// LoadFromEnv overrides default paths with environment variables if set
func (p *PathConfig) LoadFromEnv() {
	// Traefik paths
	if val := os.Getenv("TRAEFIK_DYNAMIC_CONFIG"); val != "" {
		p.TraefikDynamicConfig = val
	}
	if val := os.Getenv("TRAEFIK_STATIC_CONFIG"); val != "" {
		p.TraefikStaticConfig = val
	}
	if val := os.Getenv("TRAEFIK_ACCESS_LOG"); val != "" {
		p.TraefikAccessLog = val
	}
	if val := os.Getenv("TRAEFIK_ERROR_LOG"); val != "" {
		p.TraefikErrorLog = val
	}
	if val := os.Getenv("TRAEFIK_ASSETS_DIR"); val != "" {
		p.TraefikAssetsDir = val
	}
	if val := os.Getenv("TRAEFIK_CAPTCHA_HTML"); val != "" {
		p.TraefikCaptchaHTML = val
	}
	if val := os.Getenv("TRAEFIK_RULES_DIR"); val != "" {
		p.TraefikRulesDir = val
	}
	if val := os.Getenv("TRAEFIK_CONF_DIR"); val != "" {
		p.TraefikConfDir = val
	}

	// CrowdSec paths
	if val := os.Getenv("CROWDSEC_ACQUIS_FILE"); val != "" {
		p.CrowdSecAcquisFile = val
	}
	if val := os.Getenv("CROWDSEC_ACQUIS_DIR"); val != "" {
		p.CrowdSecAcquisDir = val
	}
	if val := os.Getenv("CROWDSEC_CONFIG_DIR"); val != "" {
		p.CrowdSecConfigDir = val
	}
	if val := os.Getenv("CROWDSEC_DATA_DIR"); val != "" {
		p.CrowdSecDataDir = val
	}

	// Manager paths
	if val := os.Getenv("MANAGER_CONFIG_DIR"); val != "" {
		p.ManagerConfigDir = val
	}
	if val := os.Getenv("MANAGER_DATA_DIR"); val != "" {
		p.ManagerDataDir = val
	}
	if val := os.Getenv("MANAGER_BACKUP_DIR"); val != "" {
		p.ManagerBackupDir = val
	}
	if val := os.Getenv("MANAGER_LOG_DIR"); val != "" {
		p.ManagerLogDir = val
	}

	// Multi-Proxy paths
	if val := os.Getenv("NGINX_CONFIG_PATH"); val != "" {
		p.NginxConfigPath = val
	}
	if val := os.Getenv("NGINX_LOG_PATH"); val != "" {
		p.NginxLogPath = val
	}
	if val := os.Getenv("CADDY_CONFIG_PATH"); val != "" {
		p.CaddyConfigPath = val
	}
	if val := os.Getenv("CADDY_LOG_PATH"); val != "" {
		p.CaddyLogPath = val
	}
	if val := os.Getenv("HAPROXY_CONFIG_PATH"); val != "" {
		p.HAProxyConfigPath = val
	}
	if val := os.Getenv("HAPROXY_SOCKET_PATH"); val != "" {
		p.HAProxySocketPath = val
	}
	if val := os.Getenv("ZORAXY_CONFIG_PATH"); val != "" {
		p.ZoraxyConfigPath = val
	}

	// Backward compatibility: If TRAEFIK_CAPTCHA_HTML not set but old path exists, try to detect
	// Check if captcha HTML should be in conf dir instead of assets dir
	if os.Getenv("TRAEFIK_CAPTCHA_HTML") == "" {
		// If dynamic config points to a rules/ subdirectory, assume conf/ structure
		if filepath.Dir(p.TraefikDynamicConfig) != "/etc/traefik" {
			baseDir := filepath.Dir(filepath.Dir(p.TraefikDynamicConfig))
			p.TraefikCaptchaHTML = filepath.Join(baseDir, "conf", "captcha.html")
		}
	}
}

// GetProxyPaths returns paths relevant to the current proxy type
func (p *PathConfig) GetProxyPaths(proxyType string) map[string]string {
	paths := make(map[string]string)

	switch proxyType {
	case "traefik":
		paths["dynamic_config"] = p.TraefikDynamicConfig
		paths["static_config"] = p.TraefikStaticConfig
		paths["access_log"] = p.TraefikAccessLog
		paths["error_log"] = p.TraefikErrorLog
		paths["assets_dir"] = p.TraefikAssetsDir
		paths["captcha_html"] = p.TraefikCaptchaHTML
		paths["rules_dir"] = p.TraefikRulesDir
		paths["conf_dir"] = p.TraefikConfDir
	case "nginx":
		paths["config_path"] = p.NginxConfigPath
		paths["log_path"] = p.NginxLogPath
	case "caddy":
		paths["config_path"] = p.CaddyConfigPath
		paths["log_path"] = p.CaddyLogPath
	case "haproxy":
		paths["config_path"] = p.HAProxyConfigPath
		paths["socket_path"] = p.HAProxySocketPath
	case "zoraxy":
		paths["config_path"] = p.ZoraxyConfigPath
	}

	return paths
}

// ValidateRequired validates that critical paths are set
func (p *PathConfig) ValidateRequired(proxyType string) error {
	switch proxyType {
	case "traefik":
		if p.TraefikDynamicConfig == "" {
			return fmt.Errorf("TRAEFIK_DYNAMIC_CONFIG must be set")
		}
		if p.TraefikStaticConfig == "" {
			return fmt.Errorf("TRAEFIK_STATIC_CONFIG must be set")
		}
	case "nginx":
		if p.NginxConfigPath == "" {
			return fmt.Errorf("NGINX_CONFIG_PATH must be set")
		}
	case "caddy":
		if p.CaddyConfigPath == "" {
			return fmt.Errorf("CADDY_CONFIG_PATH must be set")
		}
	case "haproxy":
		if p.HAProxyConfigPath == "" {
			return fmt.Errorf("HAPROXY_CONFIG_PATH must be set")
		}
	}

	// Validate manager paths (always required)
	if p.ManagerDataDir == "" {
		return fmt.Errorf("MANAGER_DATA_DIR must be set")
	}

	return nil
}

// ToMap converts PathConfig to a map for serialization
func (p *PathConfig) ToMap() map[string]interface{} {
	return map[string]interface{}{
		// Traefik
		"traefik_dynamic_config": p.TraefikDynamicConfig,
		"traefik_static_config":  p.TraefikStaticConfig,
		"traefik_access_log":     p.TraefikAccessLog,
		"traefik_error_log":      p.TraefikErrorLog,
		"traefik_assets_dir":     p.TraefikAssetsDir,
		"traefik_captcha_html":   p.TraefikCaptchaHTML,
		"traefik_rules_dir":      p.TraefikRulesDir,
		"traefik_conf_dir":       p.TraefikConfDir,
		// CrowdSec
		"crowdsec_acquis_file": p.CrowdSecAcquisFile,
		"crowdsec_acquis_dir":  p.CrowdSecAcquisDir,
		"crowdsec_config_dir":  p.CrowdSecConfigDir,
		"crowdsec_data_dir":    p.CrowdSecDataDir,
		// Manager
		"manager_config_dir": p.ManagerConfigDir,
		"manager_data_dir":   p.ManagerDataDir,
		"manager_backup_dir": p.ManagerBackupDir,
		"manager_log_dir":    p.ManagerLogDir,
		// Multi-Proxy
		"nginx_config_path":   p.NginxConfigPath,
		"nginx_log_path":      p.NginxLogPath,
		"caddy_config_path":   p.CaddyConfigPath,
		"caddy_log_path":      p.CaddyLogPath,
		"haproxy_config_path": p.HAProxyConfigPath,
		"haproxy_socket_path": p.HAProxySocketPath,
		"zoraxy_config_path":  p.ZoraxyConfigPath,
	}
}
