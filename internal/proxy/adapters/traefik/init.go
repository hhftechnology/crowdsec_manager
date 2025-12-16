package traefik

import (
	"crowdsec-manager/internal/proxy"
)

// init registers the Traefik adapter with the global proxy registry
func init() {
	proxy.RegisterAdapter(proxy.ProxyTypeTraefik, NewTraefikAdapter)
}