package standalone

import (
	"crowdsec-manager/internal/proxy"
)

// init registers the Standalone adapter with the global proxy registry
func init() {
	proxy.RegisterAdapter(proxy.ProxyTypeStandalone, NewStandaloneAdapter)
}