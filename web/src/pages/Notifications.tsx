import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { Save, RefreshCw, AlertTriangle, CheckCircle, Info } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'

interface DiscordConfig {
  enabled: boolean
  webhook_id: string
  webhook_token: string
  geoapify_key: string
  crowdsec_cti_api_key: string
  crowdsec_restarted?: boolean
  manually_configured?: boolean
  config_source?: string
}

export default function Notifications() {
  const [config, setConfig] = useState<DiscordConfig>({
    enabled: false,
    webhook_id: '',
    webhook_token: '',
    geoapify_key: '',
    crowdsec_cti_api_key: '',
  })
  const [webhookUrl, setWebhookUrl] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [restarting, setRestarting] = useState(false)

  useEffect(() => {
    fetchConfig()
  }, [])

  useEffect(() => {
    if (config.webhook_id && config.webhook_token) {
      setWebhookUrl(`https://discord.com/api/webhooks/${config.webhook_id}/${config.webhook_token}`)
    }
  }, [config.webhook_id, config.webhook_token])

  const fetchConfig = async () => {
    try {
      const response = await fetch('/api/notifications/discord')
      const data = await response.json()
      if (data.success) {
        setConfig(data.data)
      } else {
        toast.error('Failed to load configuration: ' + data.error)
      }
    } catch (error) {
      toast.error('Failed to load configuration')
      console.error(error)
    } finally {
      setLoading(false)
    }
  }

  const handleWebhookUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const url = e.target.value
    setWebhookUrl(url)

    // Parse ID and Token from URL
    // Format: https://discord.com/api/webhooks/{id}/{token}
    const match = url.match(/https:\/\/discord\.com\/api\/webhooks\/(\d+)\/([a-zA-Z0-9_-]+)/)
    if (match) {
      setConfig(prev => ({
        ...prev,
        webhook_id: match[1],
        webhook_token: match[2]
      }))
    }
  }

  const handleSave = async (shouldRestart = false) => {
    setSaving(true)
    if (shouldRestart) {
      setRestarting(true)
    }

    try {
      const response = await fetch('/api/notifications/discord', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...config,
          crowdsec_restarted: shouldRestart
        }),
      })
      const data = await response.json()
      
      if (data.success) {
        toast.success(shouldRestart ? 'Configuration saved and CrowdSec restarting...' : 'Configuration saved successfully')
        setConfig(data.data)
      } else {
        toast.error('Failed to save configuration: ' + data.error)
      }
    } catch (error) {
      toast.error('Failed to save configuration')
      console.error(error)
    } finally {
      setSaving(false)
      setRestarting(false)
    }
  }

  if (loading) {
    return <div className="flex items-center justify-center h-full">Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Notifications</h1>
        <p className="text-muted-foreground">
          Configure notification channels for CrowdSec alerts.
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <CardTitle>Discord Integration</CardTitle>
              {config.enabled && <CheckCircle className="h-5 w-5 text-green-500" />}
            </div>
            <div className="flex items-center space-x-2">
              <Label htmlFor="discord-enabled">Enable</Label>
              <Switch
                id="discord-enabled"
                checked={config.enabled}
                onCheckedChange={(checked) => setConfig(prev => ({ ...prev, enabled: checked }))}
              />
            </div>
          </div>
          <CardDescription>
            Send alerts to a Discord channel using Webhooks.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {config.manually_configured && (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertTitle>Existing Configuration Detected</AlertTitle>
              <AlertDescription>
                {config.config_source === 'container' && (
                  <>A manual Discord configuration was found in the CrowdSec container. The values below have been pre-populated from your existing setup.</>
                )}
                {config.config_source === 'both' && (
                  <>Discord notifications are configured in both the database and container. You can update them here to synchronize both sources.</>
                )}
              </AlertDescription>
            </Alert>
          )}

          <div className="space-y-2">
            <Label htmlFor="webhook-url">
              Webhook URL
              {config.manually_configured && (
                <span className="ml-2 text-xs text-muted-foreground font-normal">(Pre-populated from existing config)</span>
              )}
            </Label>
            <Input
              id="webhook-url"
              placeholder="https://discord.com/api/webhooks/..."
              value={webhookUrl}
              onChange={handleWebhookUrlChange}
            />
            <p className="text-sm text-muted-foreground">
              Paste the full Webhook URL from Discord channel settings.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="geoapify-key">
                Geoapify API Key
                {config.manually_configured && config.geoapify_key && (
                  <span className="ml-2 text-xs text-muted-foreground font-normal">(Pre-populated)</span>
                )}
              </Label>
              <Input
                id="geoapify-key"
                type="password"
                value={config.geoapify_key}
                onChange={(e) => setConfig(prev => ({ ...prev, geoapify_key: e.target.value }))}
              />
              <p className="text-sm text-muted-foreground">
                Required for static map generation.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="cti-key">CrowdSec CTI Key (Optional)</Label>
              <Input
                id="cti-key"
                type="password"
                value={config.crowdsec_cti_api_key}
                onChange={(e) => setConfig(prev => ({ ...prev, crowdsec_cti_api_key: e.target.value }))}
              />
              <p className="text-sm text-muted-foreground">
                For enhanced IP information and maliciousness scores.
              </p>
            </div>
          </div>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Restart Required</AlertTitle>
            <AlertDescription>
              Changes to notification settings require a CrowdSec container restart to take effect.
            </AlertDescription>
          </Alert>

          <div className="flex justify-end space-x-4">
            <Button 
              variant="outline" 
              onClick={() => handleSave(true)}
              disabled={saving || restarting}
            >
              {restarting ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  Restarting...
                </>
              ) : (
                <>
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Save & Restart
                </>
              )}
            </Button>
            <Button onClick={() => handleSave(false)} disabled={saving}>
              <Save className="mr-2 h-4 w-4" />
              Save Only
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
