package zoraxy

import "github.com/crowdsecurity/crowdsec-manager/internal/proxy"

func init() {
	proxy.Register(NewZoraxyAdapter())
}
