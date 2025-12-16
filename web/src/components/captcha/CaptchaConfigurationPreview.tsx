import { ProxyType } from '@/lib/proxy-types'
import { CaptchaStatus } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { 
  Eye, 
  Code, 
  FileText, 
  Settings, 
  CheckCircle, 
  XCircle, 
  AlertTriangle,
  Info,
  ExternalLink
} from 'lucide-react'

interface CaptchaConfigurationPreviewProps {
  provider: string
  siteKey: string
  proxyType: ProxyType
  status?: CaptchaStatus
}

export function CaptchaConfigurationPreview({ 
  provider, 
  siteKey, 
  proxyType, 
  status 
}: CaptchaConfigurationPreviewProps) {
  const getProviderInfo = (providerId: string) => {
    const providers = {
      turnstile: {
        name: 'Cloudflare Turnstile',
        scriptUrl: 'https://challenges.cloudflare.com/turnstile/v0/api.js',
        className: 'cf-turnstile',
        testUrl: 'https://developers.cloudflare.com/turnstile/get-started/demo/'
      },
      recaptcha: {
        name: 'Google reCAPTCHA',
        scriptUrl: 'https://www.google.com/recaptcha/api.js',
        className: 'g-recaptcha',
        testUrl: 'https://www.google.com/recaptcha/api2/demo'
      },
      hcaptcha: {
        name: 'hCaptcha',
        scriptUrl: 'https://js.hcaptcha.com/1/api.js',
        className: 'h-captcha',
        testUrl: 'https://accounts.hcaptcha.com/demo'
      }
    }
    return providers[providerId as keyof typeof providers] || providers.turnstile
  }

  const providerInfo = getProviderInfo(provider)
  const hasConfiguration = status?.configured || false
  const hasValidKeys = siteKey.trim().length > 0

  const generateCaptchaHTML = () => {
    const template = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification</title>
    <script src="${providerInfo.scriptUrl}" async defer></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 500px;
            text-align: center;
        }
        h1 { color: #333; margin-bottom: 10px; }
        p { color: #666; margin-bottom: 30px; }
        .${providerInfo.className} { display: inline-block; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Verification</h1>
        <p>Please complete the security check below to continue</p>
        <form id="captcha-form" action="{{.RedirectURL}}" method="POST">
            <div class="${providerInfo.className}" data-sitekey="${siteKey || '{{.SiteKey}}'}"></div>
            <input type="hidden" name="crowdsec_captcha" value="{{.CaptchaValue}}">
        </form>
    </div>
</body>
</html>`
    return template
  }

  const generateTraefikConfig = () => {
    return `http:
  middlewares:
    crowdsec-bouncer-traefik-plugin:
      plugin:
        crowdsec-bouncer-traefik-plugin:
          enabled: true
          logLevel: INFO
          crowdsecMode: live
          crowdsecLapiKey: "{{CROWDSEC_LAPI_KEY}}"
          crowdsecLapiHost: "crowdsec:8080"
          crowdsecLapiScheme: http
          crowdsecCapiMachineId: "{{MACHINE_ID}}"
          crowdsecCapiPassword: "{{MACHINE_PASSWORD}}"
          crowdsecCapiScenarios:
            - crowdsecurity/http-path-traversal-probing
            - crowdsecurity/http-xss-probing
          # Captcha Configuration
          captchaProvider: ${provider}
          captchaSiteKey: "${siteKey || '{{SITE_KEY}}'}"
          captchaSecretKey: "{{SECRET_KEY}}"
          captchaHTMLFilePath: "/etc/traefik/conf/captcha.html"
          captchaGracePeriodSeconds: 1800`
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="h-5 w-5" />
            Configuration Preview
          </CardTitle>
          <CardDescription>
            Preview of your captcha configuration for {providerInfo.name}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Settings className="h-4 w-4" />
                <span className="font-medium">Provider</span>
              </div>
              <p className="text-sm text-muted-foreground">{providerInfo.name}</p>
              <Badge variant="outline" className="mt-2">{provider}</Badge>
            </div>

            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <FileText className="h-4 w-4" />
                <span className="font-medium">Site Key</span>
              </div>
              <p className="text-sm text-muted-foreground font-mono">
                {siteKey ? `${siteKey.substring(0, 8)}...` : 'Not configured'}
              </p>
              {hasValidKeys ? (
                <Badge variant="default" className="mt-2 bg-green-100 text-green-800">
                  <CheckCircle className="h-3 w-3 mr-1" />
                  Valid
                </Badge>
              ) : (
                <Badge variant="secondary" className="mt-2">
                  <XCircle className="h-3 w-3 mr-1" />
                  Missing
                </Badge>
              )}
            </div>

            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="h-4 w-4" />
                <span className="font-medium">Status</span>
              </div>
              <p className="text-sm text-muted-foreground">
                {hasConfiguration ? 'Configured' : 'Not configured'}
              </p>
              {hasConfiguration ? (
                <Badge variant="default" className="mt-2 bg-green-100 text-green-800">
                  Active
                </Badge>
              ) : (
                <Badge variant="secondary" className="mt-2">
                  Inactive
                </Badge>
              )}
            </div>
          </div>

          {!hasValidKeys && (
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                Please configure your site key and secret key in the Setup tab to see a complete preview.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* HTML Preview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Code className="h-5 w-5" />
            Captcha HTML Template
          </CardTitle>
          <CardDescription>
            Preview of the captcha challenge page that users will see
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="relative">
            <pre className="bg-muted p-4 rounded-lg text-sm overflow-x-auto max-h-64">
              <code>{generateCaptchaHTML()}</code>
            </pre>
          </div>
          
          <div className="flex items-center justify-between">
            <div className="text-sm text-muted-foreground">
              This HTML will be served when users need to complete a captcha challenge
            </div>
            <Button variant="outline" size="sm" asChild>
              <a href={providerInfo.testUrl} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-4 w-4 mr-2" />
                Test Provider
              </a>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Traefik Configuration Preview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Traefik Configuration
          </CardTitle>
          <CardDescription>
            Preview of the Traefik middleware configuration
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="relative">
            <pre className="bg-muted p-4 rounded-lg text-sm overflow-x-auto max-h-64">
              <code>{generateTraefikConfig()}</code>
            </pre>
          </div>
          
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              This configuration will be automatically applied to your Traefik dynamic_config.yml file.
              Sensitive values like secret keys will be properly secured.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      {/* Configuration Status */}
      {status && (
        <Card>
          <CardHeader>
            <CardTitle>Current Configuration Status</CardTitle>
            <CardDescription>
              Status of your current captcha configuration
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <span className="text-sm">Configuration Saved</span>
                  {status.configSaved ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                </div>
                
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <span className="text-sm">Captcha HTML Exists</span>
                  {status.captchaHTMLExists ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <span className="text-sm">Middleware Configured</span>
                  {status.configured ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                </div>
                
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <span className="text-sm">Fully Implemented</span>
                  {status.implemented ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                </div>
              </div>
            </div>

            {status.provider && (
              <div className="mt-4 p-3 bg-muted rounded-lg">
                <div className="text-sm">
                  <span className="font-medium">Current Provider:</span> {status.provider}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}