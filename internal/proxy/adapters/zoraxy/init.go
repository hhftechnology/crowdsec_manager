package zoraxy

import (
	"crowdsec-manager/internal/proxy"
)

// init registers the Zoraxy adapter with the global proxy registry
func init() {
	proxy.RegisterAdapter(proxy.ProxyTypeZoraxy, NewZoraxyAdapter)
}