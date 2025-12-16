package caddy

import (
	"crowdsec-manager/internal/proxy"
)

// init registers the Caddy adapter with the global proxy registry
func init() {
	proxy.RegisterAdapter(proxy.ProxyTypeCaddy, NewCaddyAdapter)
}