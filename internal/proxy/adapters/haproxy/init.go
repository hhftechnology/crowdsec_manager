package haproxy

import (
	"crowdsec-manager/internal/proxy"
)

// init registers the HAProxy adapter with the global proxy registry
func init() {
	proxy.RegisterAdapter(proxy.ProxyTypeHAProxy, NewHAProxyAdapter)
}