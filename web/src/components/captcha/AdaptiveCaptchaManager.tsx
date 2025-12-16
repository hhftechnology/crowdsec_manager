import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { CaptchaSetupRequest, CaptchaStatus } from '@/lib/api'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { 
  Shield, 
  Eye, 
  EyeOff, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Info,
  Network,
  Settings,
  RefreshCw,
  ExternalLink
} from 'lucide-react'
import { FeatureAvailabilityIndicator } from '../whitelist/FeatureAvailabilityIndicator'
import { CaptchaProviderSelector } from './CaptchaProviderSelector'
import { CaptchaConfigurationPreview } from './CaptchaConfigurationPreview'
import { CaptchaStatusMonitor } from './CaptchaStatusMonitor'

interface AdaptiveCaptchaManagerProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
}

export function AdaptiveCaptchaManager({ proxyType, supportedFeatures }: AdaptiveCaptchaManagerProps) {
  const queryClient = useQueryClient()
  const [provider, setProvider] = useState('turnstile')
  const [siteKey, setSiteKey] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [showSecretKey, setShowSecretKey] = useState(false)

  const supportsCaptcha = supportedFeatures.includes('captcha')
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)

  const { data: captchaStatus, isLoading: statusLoading, refetch: refetchStatus } = useQuery({
    queryKey: ['captcha-status'],
    queryFn: async () => {
      const response = await api.captcha.getStatus()
      return response.data.data as CaptchaStatus
    },
    refetchInterval: supportsCaptcha ? 30000 : false, // Auto-refresh every 30s if supported
  })

  const setupCaptchaMutation = useMutation({
    mutationFn: (data: CaptchaSetupRequest) => api.captcha.setup(data),
    onSuccess: () => {
      toast.success('Captcha configured successfully')
      queryClient.invalidateQueries({ queryKey: ['captcha-status'] })
      // Clear sensitive data after successful setup
      setSiteKey('')
      setSecretKey('')
    },
    onError: (error: any) => {
      toast.error(`Failed to configure captcha: ${error.response?.data?.error || error.message}`)
    },
  })

  // Pre-populate form with existing configuration
  useEffect(() => {
    if (captchaStatus && captchaStatus.configured) {
      if (captchaStatus.provider) {
        setProvider(captchaStatus.provider)
      }
      if (captchaStatus.site_key) {
        setSiteKey(captchaStatus.site_key)
      }
      if (captchaStatus.secret_key) {
        setSecretKey(captchaStatus.secret_key)
      }
    }
  }, [captchaStatus])

  const handleSetupCaptcha = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!siteKey.trim() || !secretKey.trim()) {
      toast.error('Please enter both Site Key and Secret Key')
      return
    }

    setupCaptchaMutation.mutate({
      provider,
      site_key: siteKey,
      secret_key: secretKey,
    })
  }

  const handleRefreshStatus = () => {
    refetchStatus()
    toast.info('Refreshing captcha status...')
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Captcha Protection Management</h1>
        <p className="text-muted-foreground mt-2">
          Configure captcha middleware protection for {proxyName}
        </p>
      </div>

      {/* Proxy Feature Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Proxy Configuration
          </CardTitle>
          <CardDescription>
            Current proxy type and captcha feature availability
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div>
              <p className="font-medium">Current Proxy Type</p>
              <p className="text-sm text-muted-foreground">
                {proxyName} {proxyType === 'zoraxy' && '(Experimental)'}
              </p>
            </div>
            <Badge variant="outline">{proxyName}</Badge>
          </div>

          <FeatureAvailabilityIndicator
            feature="captcha"
            available={supportsCaptcha}
            proxyType={proxyType}
            description="Configure captcha middleware protection at the reverse proxy level"
          />

          {!supportsCaptcha && (
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                {proxyName} does not support captcha middleware configuration. 
                Consider implementing captcha protection at the application level or using a different reverse proxy.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Captcha Status Monitor */}
      {supportsCaptcha && (
        <CaptchaStatusMonitor 
          status={captchaStatus}
          isLoading={statusLoading}
          onRefresh={handleRefreshStatus}
          proxyType={proxyType}
        />
      )}

      {/* Captcha Configuration */}
      {supportsCaptcha && (
        <Tabs defaultValue="setup" className="space-y-4">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="setup">Setup</TabsTrigger>
            <TabsTrigger value="preview">Preview</TabsTrigger>
            <TabsTrigger value="advanced">Advanced</TabsTrigger>
          </TabsList>

          <TabsContent value="setup">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Captcha Configuration
                </CardTitle>
                <CardDescription>
                  Configure captcha provider and authentication keys
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSetupCaptcha} className="space-y-6">
                  <CaptchaProviderSelector
                    value={provider}
                    onChange={setProvider}
                    proxyType={proxyType}
                  />

                  <Separator />

                  <div className="space-y-4">
                    <h4 className="font-medium">Authentication Keys</h4>
                    
                    <div className="space-y-2">
                      <Label htmlFor="site-key">Site Key</Label>
                      <Input
                        id="site-key"
                        type="text"
                        placeholder="Enter your captcha site key"
                        value={siteKey}
                        onChange={(e) => setSiteKey(e.target.value)}
                        className="font-mono"
                      />
                      <p className="text-xs text-muted-foreground">
                        The public site key provided by your captcha provider
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="secret-key">Secret Key</Label>
                      <div className="relative">
                        <Input
                          id="secret-key"
                          type={showSecretKey ? "text" : "password"}
                          placeholder="Enter your captcha secret key"
                          value={secretKey}
                          onChange={(e) => setSecretKey(e.target.value)}
                          className="font-mono pr-10"
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                          onClick={() => setShowSecretKey(!showSecretKey)}
                        >
                          {showSecretKey ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        The private secret key provided by your captcha provider
                      </p>
                    </div>
                  </div>

                  <Alert>
                    <Info className="h-4 w-4" />
                    <AlertDescription>
                      Setting up captcha will update your {proxyName} configuration and restart the necessary services. 
                      This may cause a brief interruption in service.
                    </AlertDescription>
                  </Alert>

                  <Button
                    type="submit"
                    className="w-full"
                    disabled={setupCaptchaMutation.isPending || !siteKey.trim() || !secretKey.trim()}
                  >
                    {setupCaptchaMutation.isPending ? (
                      <>
                        <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                        Configuring Captcha...
                      </>
                    ) : (
                      <>
                        <Shield className="mr-2 h-4 w-4" />
                        Configure Captcha Protection
                      </>
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="preview">
            <CaptchaConfigurationPreview
              provider={provider}
              siteKey={siteKey}
              proxyType={proxyType}
              status={captchaStatus}
            />
          </TabsContent>

          <TabsContent value="advanced">
            <Card>
              <CardHeader>
                <CardTitle>Advanced Configuration</CardTitle>
                <CardDescription>
                  Advanced captcha settings and troubleshooting
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    Advanced configuration options are managed through {proxyName} configuration files. 
                    Refer to the documentation for manual configuration options.
                  </AlertDescription>
                </Alert>

                <div className="space-y-4">
                  <div className="p-4 border rounded-lg">
                    <h4 className="font-medium mb-2">Configuration Files</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Dynamic Config:</span>
                        <code className="text-xs bg-muted px-2 py-1 rounded">/etc/traefik/dynamic_config.yml</code>
                      </div>
                      <div className="flex justify-between">
                        <span>Captcha HTML:</span>
                        <code className="text-xs bg-muted px-2 py-1 rounded">/etc/traefik/conf/captcha.html</code>
                      </div>
                      <div className="flex justify-between">
                        <span>CrowdSec Profiles:</span>
                        <code className="text-xs bg-muted px-2 py-1 rounded">/etc/crowdsec/profiles.yaml</code>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 border rounded-lg">
                    <h4 className="font-medium mb-2">Troubleshooting</h4>
                    <div className="space-y-2 text-sm text-muted-foreground">
                      <p>• Ensure your captcha provider keys are valid and active</p>
                      <p>• Check that the captcha HTML file is accessible</p>
                      <p>• Verify {proxyName} can reach the captcha provider's API</p>
                      <p>• Review container logs for configuration errors</p>
                    </div>
                  </div>

                  <Button variant="outline" className="w-full" asChild>
                    <a href="/docs/features/captcha" target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="mr-2 h-4 w-4" />
                      View Captcha Documentation
                    </a>
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      )}

      {/* Fallback for unsupported proxies */}
      {!supportsCaptcha && (
        <Card>
          <CardHeader>
            <CardTitle>Alternative Captcha Solutions</CardTitle>
            <CardDescription>
              Captcha protection options for {proxyName}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>
                While {proxyName} doesn't support built-in captcha middleware, you can still implement captcha protection:
              </AlertDescription>
            </Alert>

            <div className="space-y-3">
              <div className="p-4 border rounded-lg">
                <h4 className="font-medium">Application-Level Captcha</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Implement captcha directly in your web applications using provider SDKs
                </p>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-medium">External Captcha Services</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Use cloud-based captcha services that integrate with your applications
                </p>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-medium">Upgrade to Traefik</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Consider migrating to Traefik for full captcha middleware support
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}