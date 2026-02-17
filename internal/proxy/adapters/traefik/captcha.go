package traefik

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// CaptchaMgr handles captcha challenge configuration for Traefik.
type CaptchaMgr struct {
	docker *docker.Client
	cfg    *config.Config
	paths  config.ProxyPaths
}

func (m *CaptchaMgr) Status(ctx context.Context) (*proxy.CaptchaStatus, error) {
	status := &proxy.CaptchaStatus{}

	// Check if captcha HTML exists.
	data, err := m.docker.ReadFileFromContainer(ctx, m.cfg.ProxyContainer, m.paths.CaptchaHTML)
	if err == nil && len(data) > 0 {
		status.HTMLExists = true
		// Try to detect provider from HTML content.
		html := string(data)
		switch {
		case strings.Contains(html, "turnstile"):
			status.Provider = "turnstile"
		case strings.Contains(html, "recaptcha"):
			status.Provider = "recaptcha"
		case strings.Contains(html, "hcaptcha"):
			status.Provider = "hcaptcha"
		}
		status.Enabled = true
		status.ConfigOK = true
	}

	return status, nil
}

func (m *CaptchaMgr) Setup(ctx context.Context, cfg proxy.CaptchaConfig) error {
	html := generateCaptchaHTML(cfg.Provider, cfg.SiteKey)

	if err := m.docker.WriteFileToContainer(ctx, m.cfg.ProxyContainer, m.paths.CaptchaHTML, []byte(html)); err != nil {
		return fmt.Errorf("write captcha HTML: %w", err)
	}

	return nil
}

func (m *CaptchaMgr) Disable(ctx context.Context) error {
	// Overwrite with empty file to disable.
	return m.docker.WriteFileToContainer(ctx, m.cfg.ProxyContainer, m.paths.CaptchaHTML, []byte(""))
}

func generateCaptchaHTML(provider, siteKey string) string {
	var scriptTag, widgetDiv string

	switch provider {
	case "turnstile":
		scriptTag = `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
		widgetDiv = fmt.Sprintf(`<div class="cf-turnstile" data-sitekey="%s" data-callback="onCaptchaSuccess"></div>`, siteKey)
	case "recaptcha":
		scriptTag = `<script src="https://www.google.com/recaptcha/api.js" async defer></script>`
		widgetDiv = fmt.Sprintf(`<div class="g-recaptcha" data-sitekey="%s" data-callback="onCaptchaSuccess"></div>`, siteKey)
	case "hcaptcha":
		scriptTag = `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>`
		widgetDiv = fmt.Sprintf(`<div class="h-captcha" data-sitekey="%s" data-callback="onCaptchaSuccess"></div>`, siteKey)
	default:
		scriptTag = "<!-- unknown captcha provider -->"
		widgetDiv = "<p>Unknown captcha provider</p>"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check</title>
    %s
    <style>
        body { font-family: -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
        .container { text-align: center; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 1rem; }
        p { color: #666; margin-bottom: 2rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Check</h1>
        <p>Please complete the challenge below to continue.</p>
        %s
    </div>
    <script>
        function onCaptchaSuccess(token) {
            document.cookie = "crowdsec_captcha=" + token + "; path=/; max-age=86400";
            window.location.reload();
        }
    </script>
</body>
</html>`, scriptTag, widgetDiv)
}
