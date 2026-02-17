package nginx

import "github.com/crowdsecurity/crowdsec-manager/internal/proxy"

func init() {
	proxy.Register(NewNginxAdapter())
}
