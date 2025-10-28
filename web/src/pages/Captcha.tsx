import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { CaptchaSetupRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { CheckCircle2, XCircle, Shield } from 'lucide-react'

export default function Captcha() {
  const queryClient = useQueryClient()
  const [provider, setProvider] = useState('recaptcha')
  const [siteKey, setSiteKey] = useState('')
  const [secretKey, setSecretKey] = useState('')

  const { data: statusData, isLoading } = useQuery({
    queryKey: ['captcha-status'],
    queryFn: async () => {
      const response = await api.captcha.getStatus()
      return response.data.data
    },
  })

  const setupMutation = useMutation({
    mutationFn: (data: CaptchaSetupRequest) => api.captcha.setup(data),
    onSuccess: () => {
      toast.success('Captcha configured successfully')
      setSiteKey('')
      setSecretKey('')
      queryClient.invalidateQueries({ queryKey: ['captcha-status'] })
    },
    onError: () => {
      toast.error('Failed to configure captcha')
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!provider.trim()) {
      toast.error('Please select a provider')
      return
    }

    if (!siteKey.trim()) {
      toast.error('Please enter a site key')
      return
    }

    if (!secretKey.trim()) {
      toast.error('Please enter a secret key')
      return
    }

    setupMutation.mutate({
      provider,
      site_key: siteKey,
      secret_key: secretKey,
    })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Captcha Setup</h1>
        <p className="text-muted-foreground mt-2">
          Configure captcha protection for CrowdSec remediation
        </p>
      </div>

      {/* Current Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Captcha Status
          </CardTitle>
          <CardDescription>
            Current captcha configuration status
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="h-24 bg-muted animate-pulse rounded" />
          ) : (
            <div className="space-y-4">
              {/* Implementation Status Warning */}
              {!statusData?.implemented && (
                <div className="flex items-center gap-3 p-4 border border-yellow-500/50 bg-yellow-500/10 rounded-lg">
                  <XCircle className="h-5 w-5 text-yellow-500 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-yellow-700 dark:text-yellow-400">
                      Captcha Middleware Not Implemented
                    </p>
                    <p className="text-sm text-muted-foreground">
                      Configuration can be saved, but captcha protection is not yet active in Traefik
                    </p>
                  </div>
                </div>
              )}

              {/* Configuration Status */}
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div>
                  <p className="font-medium">Configuration Status</p>
                  <p className="text-sm text-muted-foreground">
                    {statusData?.configSaved
                      ? 'Configuration saved (not active)'
                      : 'Captcha is not configured'}
                  </p>
                </div>
                {statusData?.configSaved ? (
                  <Badge variant="outline" className="text-yellow-600">Saved</Badge>
                ) : (
                  <XCircle className="h-5 w-5 text-muted-foreground" />
                )}
              </div>

              {statusData?.configSaved && statusData.provider && (
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <p className="font-medium">Saved Provider</p>
                    <p className="text-sm text-muted-foreground capitalize">
                      {statusData.provider}
                    </p>
                  </div>
                  <Badge variant="secondary">{statusData.provider}</Badge>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Setup Form */}
      <Card>
        <CardHeader>
          <CardTitle>Configure Captcha</CardTitle>
          <CardDescription>
            Setup captcha provider credentials for bot protection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="provider">
                Captcha Provider <span className="text-destructive">*</span>
              </Label>
              <select
                id="provider"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
              >
                <option value="recaptcha">Google reCAPTCHA</option>
                <option value="hcaptcha">hCaptcha</option>
                <option value="turnstile">Cloudflare Turnstile</option>
              </select>
              <p className="text-xs text-muted-foreground">
                Select your preferred captcha provider
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="site-key">
                Site Key <span className="text-destructive">*</span>
              </Label>
              <Input
                id="site-key"
                type="text"
                placeholder="Your site key (public key)"
                value={siteKey}
                onChange={(e) => setSiteKey(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                The public site key from your captcha provider
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="secret-key">
                Secret Key <span className="text-destructive">*</span>
              </Label>
              <Input
                id="secret-key"
                type="password"
                placeholder="Your secret key (private key)"
                value={secretKey}
                onChange={(e) => setSecretKey(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                The private secret key from your captcha provider (kept secure)
              </p>
            </div>

            <Button
              type="submit"
              className="w-full"
              disabled={setupMutation.isPending}
            >
              {setupMutation.isPending ? 'Configuring...' : 'Configure Captcha'}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Provider Setup Instructions */}
      <Card>
        <CardHeader>
          <CardTitle>Setup Instructions</CardTitle>
          <CardDescription>
            How to obtain captcha credentials from different providers
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <h3 className="font-semibold">Google reCAPTCHA</h3>
            <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
              <li>Visit <a href="https://www.google.com/recaptcha/admin" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">reCAPTCHA Admin Console</a></li>
              <li>Register a new site</li>
              <li>Choose reCAPTCHA v2 or v3</li>
              <li>Add your domain</li>
              <li>Copy the Site Key and Secret Key</li>
            </ol>
          </div>

          <div className="space-y-2">
            <h3 className="font-semibold">hCaptcha</h3>
            <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
              <li>Visit <a href="https://dashboard.hcaptcha.com/signup" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">hCaptcha Dashboard</a></li>
              <li>Create a new site</li>
              <li>Add your domain</li>
              <li>Copy the Site Key and Secret Key</li>
            </ol>
          </div>

          <div className="space-y-2">
            <h3 className="font-semibold">Cloudflare Turnstile</h3>
            <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
              <li>Visit <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Cloudflare Turnstile</a></li>
              <li>Create a new site</li>
              <li>Add your domain</li>
              <li>Copy the Site Key and Secret Key</li>
            </ol>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
