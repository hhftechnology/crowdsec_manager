package nginx

import (
	"crowdsec-manager/internal/proxy"
)

// init registers the Nginx Proxy Manager adapter with the global proxy registry
func init() {
	proxy.RegisterAdapter(proxy.ProxyTypeNginx, NewNginxAdapter)
}