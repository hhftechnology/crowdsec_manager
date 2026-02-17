package config

// ProxyPaths defines filesystem paths for proxy-specific configuration files.
type ProxyPaths struct {
	DynamicConfig string
	StaticConfig  string
	AccessLog     string
	CaptchaHTML   string
}

// GetPaths returns the default file paths for a given proxy type.
func GetPaths(proxyType string) ProxyPaths {
	switch proxyType {
	case "traefik":
		return ProxyPaths{
			DynamicConfig: "/etc/traefik/dynamic_config.yml",
			StaticConfig:  "/etc/traefik/traefik.yml",
			AccessLog:     "/var/log/traefik/access.log",
			CaptchaHTML:   "/var/www/captcha/captcha.html",
		}
	case "nginx":
		return ProxyPaths{
			DynamicConfig: "/etc/nginx/conf.d/crowdsec.conf",
			StaticConfig:  "/etc/nginx/nginx.conf",
			AccessLog:     "/var/log/nginx/access.log",
			CaptchaHTML:   "/var/www/captcha/captcha.html",
		}
	case "caddy":
		return ProxyPaths{
			DynamicConfig: "/etc/caddy/Caddyfile",
			StaticConfig:  "/etc/caddy/Caddyfile",
			AccessLog:     "/var/log/caddy/access.log",
			CaptchaHTML:   "/var/www/captcha/captcha.html",
		}
	case "haproxy":
		return ProxyPaths{
			DynamicConfig: "/etc/haproxy/crowdsec.cfg",
			StaticConfig:  "/etc/haproxy/haproxy.cfg",
			AccessLog:     "/var/log/haproxy/access.log",
			CaptchaHTML:   "/var/www/captcha/captcha.html",
		}
	case "zoraxy":
		return ProxyPaths{
			DynamicConfig: "/opt/zoraxy/config/crowdsec.json",
			StaticConfig:  "/opt/zoraxy/config/config.json",
			AccessLog:     "/opt/zoraxy/log/access.log",
			CaptchaHTML:   "/opt/zoraxy/www/captcha.html",
		}
	default:
		return ProxyPaths{}
	}
}
