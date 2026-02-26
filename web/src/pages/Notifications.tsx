import { useState, useMemo, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { notificationsAPI } from '@/lib/api/notifications'
import type { NotificationConfig } from '@/lib/api/notifications'
import { FeatureWizard, StepProgress, PageHeader, QueryError } from '@/components/common'
import type { WizardStep } from '@/components/common'
import type { StepResult, FeatureDetectionResult } from '@/lib/api/types'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import {
  Bell,
  CheckCircle,
  AlertCircle,
  RefreshCw,
  Info,
  Rocket,
  Settings,
  AlertTriangle,
} from 'lucide-react'

const DISCORD_WEBHOOK_REGEX =
  /https:\/\/discord\.com\/api\/webhooks\/(\d+)\/([a-zA-Z0-9_-]+)/

function parseWebhookUrl(url: string): { webhook_id: string; webhook_token: string } | null {
  const match = url.match(DISCORD_WEBHOOK_REGEX)
  if (match) return { webhook_id: match[1], webhook_token: match[2] }
  return null
}

function buildWebhookUrl(id: string, token: string): string {
  if (!id || !token) return ''
  return `https://discord.com/api/webhooks/${id}/${token}`
}

const EMPTY_CONFIG: NotificationConfig = {
  enabled: false,
  webhook_id: '',
  webhook_token: '',
  geoapify_key: '',
  crowdsec_cti_api_key: '',
}

export default function Notifications() {
  const queryClient = useQueryClient()
  const [currentStep, setCurrentStep] = useState(0)

  // Form state
  const [enabled, setEnabled] = useState(false)
  const [webhookUrl, setWebhookUrl] = useState('')
  const [webhookId, setWebhookId] = useState('')
  const [webhookToken, setWebhookToken] = useState('')
  const [geoapifyKey, setGeoapifyKey] = useState('')
  const [ctiKey, setCtiKey] = useState('')
  const [rawYaml, setRawYaml] = useState('')
  const [configTab, setConfigTab] = useState<'simple' | 'advanced'>('simple')

  // Wizard state
  const [applySteps, setApplySteps] = useState<StepResult[]>([])
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(new Set())
  const [errorSteps, setErrorSteps] = useState<Set<string>>(new Set())

  // ── Detection query ────────────────────────────────────────────────────────
  const {
    data: detection,
    isLoading: detecting,
    isError: detectError,
    error: detectErr,
    refetch: redetect,
  } = useQuery({
    queryKey: ['notifications-detect'],
    queryFn: async () => {
      const res = await notificationsAPI.detect()
      return res.data.data as FeatureDetectionResult
    },
  })

  // ── Current config query (used for verify step) ────────────────────────────
  const { data: currentConfig, refetch: refetchConfig } = useQuery({
    queryKey: ['notifications-discord-config'],
    queryFn: async () => {
      const res = await notificationsAPI.getDiscordConfig()
      return res.data.data
    },
  })

  // ── Pre-populate from detection ────────────────────────────────────────────
  useEffect(() => {
    if (detection?.detected_values) {
      const vals = detection.detected_values
      if (vals.webhook_id && typeof vals.webhook_id === 'string') {
        setWebhookId(vals.webhook_id)
      }
      if (vals.webhook_token && typeof vals.webhook_token === 'string') {
        setWebhookToken(vals.webhook_token)
      }
      if (vals.geoapify_key && typeof vals.geoapify_key === 'string') {
        setGeoapifyKey(vals.geoapify_key)
      }
      if (vals.crowdsec_cti_api_key && typeof vals.crowdsec_cti_api_key === 'string') {
        setCtiKey(vals.crowdsec_cti_api_key)
      }
      if (vals.enabled && typeof vals.enabled === 'boolean') {
        setEnabled(vals.enabled)
      }
      setCompletedSteps((prev) => new Set([...prev, 'detect']))
    }
  }, [detection])

  // Keep webhook URL display in sync with parsed id/token
  useEffect(() => {
    const url = buildWebhookUrl(webhookId, webhookToken)
    if (url) setWebhookUrl(url)
  }, [webhookId, webhookToken])

  // Pre-populate from existing config if detection has no values
  useEffect(() => {
    if (currentConfig && !detection?.detected_values) {
      setEnabled(currentConfig.enabled)
      if (currentConfig.webhook_id) setWebhookId(currentConfig.webhook_id)
      if (currentConfig.webhook_token) setWebhookToken(currentConfig.webhook_token)
      if (currentConfig.geoapify_key) setGeoapifyKey(currentConfig.geoapify_key)
      if (currentConfig.crowdsec_cti_api_key) setCtiKey(currentConfig.crowdsec_cti_api_key)
    }
  }, [currentConfig, detection])

  // ── Webhook URL change handler ─────────────────────────────────────────────
  const handleWebhookUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const url = e.target.value
    setWebhookUrl(url)
    const parsed = parseWebhookUrl(url)
    if (parsed) {
      setWebhookId(parsed.webhook_id)
      setWebhookToken(parsed.webhook_token)
    }
  }

  // ── Load YAML preview when switching to advanced tab ───────────────────────
  const handleConfigTabChange = (value: string) => {
    const tab = value as 'simple' | 'advanced'
    setConfigTab(tab)
    if (tab === 'advanced' && !rawYaml) {
      const source = currentConfig?.manually_configured ? 'container' : 'default'
      notificationsAPI
        .previewDiscordConfig(source)
        .then((res) => {
          if (res.data.data) setRawYaml(res.data.data)
        })
        .catch(() => toast.error('Failed to load YAML preview'))
    }
  }

  const configPayload = (): NotificationConfig => ({
    enabled,
    webhook_id: webhookId,
    webhook_token: webhookToken,
    geoapify_key: geoapifyKey,
    crowdsec_cti_api_key: ctiKey,
    raw_yaml: configTab === 'advanced' ? rawYaml : '',
  })

  const canProceedConfigure =
    configTab === 'simple'
      ? webhookId.length > 0 && webhookToken.length > 0
      : rawYaml.trim().length > 0

  // ── Save mutation ──────────────────────────────────────────────────────────
  const saveMutation = useMutation({
    mutationFn: () => notificationsAPI.saveConfig(configPayload()),
    onSuccess: () => {
      toast.success('Configuration saved')
      setCompletedSteps((prev) => new Set([...prev, 'configure', 'review']))
      setCurrentStep(3)
    },
    onError: () => toast.error('Failed to save configuration'),
  })

  // ── Apply mutation ─────────────────────────────────────────────────────────
  const applyMutation = useMutation({
    mutationFn: () => notificationsAPI.applyConfig(),
    onSuccess: (res) => {
      const data = res.data.data
      if (data?.steps) setApplySteps(data.steps)
      if (data?.applied) {
        toast.success('Discord notifications applied successfully!')
        setCompletedSteps((prev) => new Set([...prev, 'apply']))
        setCurrentStep(4)
      } else {
        toast.error('Some steps failed. Check details below.')
        setErrorSteps((prev) => new Set([...prev, 'apply']))
      }
      queryClient.invalidateQueries({ queryKey: ['notifications-discord-config'] })
      queryClient.invalidateQueries({ queryKey: ['notifications-detect'] })
    },
    onError: () => toast.error('Failed to apply configuration'),
  })

  const isProcessing = saveMutation.isPending || applyMutation.isPending || detecting

  // ── Wizard steps ───────────────────────────────────────────────────────────
  const steps: WizardStep[] = useMemo(
    () => [
      // ── Step 1: Detect ─────────────────────────────────────────────────────
      {
        id: 'detect',
        title: 'Detect',
        description: 'Scanning for existing Discord notification configuration',
        content: (
          <div className="space-y-4">
            {detecting ? (
              <div className="flex items-center gap-2 text-muted-foreground">
                <RefreshCw className="h-4 w-4 animate-spin" />
                Scanning configuration files and containers...
              </div>
            ) : detectError ? (
              <QueryError error={detectErr as Error} onRetry={redetect} />
            ) : detection ? (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <Badge
                    variant={
                      detection.status === 'applied'
                        ? 'default'
                        : detection.status === 'not_configured'
                        ? 'secondary'
                        : 'outline'
                    }
                  >
                    {detection.status.replace(/_/g, ' ')}
                  </Badge>
                </div>

                {/* Sources */}
                <div className="grid gap-2 sm:grid-cols-2">
                  {Object.entries(detection.sources).map(([source, found]) => (
                    <div key={source} className="flex items-center gap-2 rounded-lg border p-3">
                      {found ? (
                        <CheckCircle className="h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      ) : (
                        <AlertCircle className="h-4 w-4 text-muted-foreground shrink-0" />
                      )}
                      <span className="text-sm">{source.replace(/_/g, ' ')}</span>
                    </div>
                  ))}
                </div>

                {/* Detected values */}
                {Object.keys(detection.detected_values).length > 0 && (
                  <Alert>
                    <Info className="h-4 w-4" />
                    <AlertTitle>Values detected</AlertTitle>
                    <AlertDescription>
                      <ul className="mt-2 space-y-1 text-sm">
                        {Boolean(detection.detected_values.webhook_id) && (
                          <li>
                            Webhook ID:{' '}
                            <code className="text-xs">
                              {String(detection.detected_values.webhook_id)}
                            </code>
                          </li>
                        )}
                        {Boolean(detection.detected_values.geoapify_key) && (
                          <li>Geoapify Key: detected</li>
                        )}
                        {Boolean(detection.detected_values.crowdsec_cti_api_key) && (
                          <li>CTI API Key: detected</li>
                        )}
                      </ul>
                      <p className="mt-2 text-xs text-muted-foreground">
                        These values are pre-filled in the next step.
                      </p>
                    </AlertDescription>
                  </Alert>
                )}

                {detection.status === 'not_configured' && (
                  <Alert>
                    <Info className="h-4 w-4" />
                    <AlertTitle>No existing configuration found</AlertTitle>
                    <AlertDescription>
                      No Discord notification configuration was detected. You can set one up
                      in the next step.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            ) : null}
          </div>
        ),
      },

      // ── Step 2: Configure ──────────────────────────────────────────────────
      {
        id: 'configure',
        title: 'Configure',
        description: 'Enter your Discord webhook and optional API keys',
        canProceed: canProceedConfigure,
        content: (
          <div className="space-y-6">
            {/* Enable toggle */}
            <div className="flex items-center justify-between rounded-lg border p-4">
              <div>
                <p className="font-medium text-sm">Enable Discord notifications</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Send CrowdSec alerts to a Discord channel
                </p>
              </div>
              <Switch
                checked={enabled}
                onCheckedChange={setEnabled}
              />
            </div>

            {/* Simple / Advanced tabs */}
            <Tabs
              value={configTab}
              onValueChange={handleConfigTabChange}
            >
              <div className="flex items-center justify-between mb-4">
                <TabsList>
                  <TabsTrigger value="simple">Simple</TabsTrigger>
                  <TabsTrigger value="advanced">Advanced (YAML)</TabsTrigger>
                </TabsList>
                {configTab === 'advanced' && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      notificationsAPI
                        .previewDiscordConfig('default')
                        .then((res) => {
                          if (res.data.data) setRawYaml(res.data.data)
                        })
                        .catch(() => toast.error('Failed to load template'))
                    }
                  >
                    <RefreshCw className="h-3 w-3 mr-2" />
                    Reset to template
                  </Button>
                )}
              </div>

              <TabsContent value="simple" className="space-y-4">
                {currentConfig?.manually_configured && (
                  <Alert>
                    <Info className="h-4 w-4" />
                    <AlertTitle>Existing configuration detected</AlertTitle>
                    <AlertDescription>
                      {currentConfig.config_source === 'container_env' &&
                        'Discord configuration was detected in the CrowdSec container environment variables. Values are pre-populated below.'}
                      {currentConfig.config_source === 'container_file' &&
                        'A manual Discord configuration file was found in the CrowdSec container. Values are pre-populated below.'}
                      {(currentConfig.config_source === 'container' ||
                        !currentConfig.config_source) &&
                        'A manual Discord configuration was found in the CrowdSec container. Values are pre-populated below.'}
                      {currentConfig.config_source === 'both' &&
                        'Discord notifications are configured in both the database and container. Saving here will synchronize both sources.'}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="space-y-2">
                  <label htmlFor="webhook-url" className="text-sm font-medium">
                    Webhook URL
                  </label>
                  <Input
                    id="webhook-url"
                    placeholder="https://discord.com/api/webhooks/..."
                    value={webhookUrl}
                    onChange={handleWebhookUrlChange}
                  />
                  <p className="text-xs text-muted-foreground">
                    Paste the full Webhook URL from Discord channel settings. The ID and token
                    are extracted automatically.
                  </p>
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <label htmlFor="geoapify-key" className="text-sm font-medium">
                      Geoapify API Key
                    </label>
                    <Input
                      id="geoapify-key"
                      type="password"
                      placeholder="Geoapify API key..."
                      value={geoapifyKey}
                      onChange={(e) => setGeoapifyKey(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Required for static map generation.
                    </p>
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="cti-key" className="text-sm font-medium">
                      CrowdSec CTI Key{' '}
                      <span className="text-muted-foreground font-normal">(optional)</span>
                    </label>
                    <Input
                      id="cti-key"
                      type="password"
                      placeholder="CTI API key..."
                      value={ctiKey}
                      onChange={(e) => setCtiKey(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      For enhanced IP information and maliciousness scores.
                    </p>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="advanced" className="space-y-4">
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>Advanced configuration</AlertTitle>
                  <AlertDescription>
                    You are editing the raw discord.yaml file. Ensure your YAML is valid and
                    follows the CrowdSec notification plugin format.
                  </AlertDescription>
                </Alert>
                <Textarea
                  value={rawYaml}
                  onChange={(e) => setRawYaml(e.target.value)}
                  className="font-mono min-h-[320px]"
                  spellCheck={false}
                  placeholder="Loading YAML template..."
                />
              </TabsContent>
            </Tabs>
          </div>
        ),
      },

      // ── Step 3: Review ─────────────────────────────────────────────────────
      {
        id: 'review',
        title: 'Review',
        description: 'Review what will happen when you apply',
        content: (
          <div className="space-y-4">
            <div className="rounded-lg border p-4 space-y-3">
              <h4 className="font-medium text-sm">Configuration Summary</h4>
              <div className="grid gap-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Notifications enabled</span>
                  <span className="font-medium">{enabled ? 'Yes' : 'No'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Webhook ID</span>
                  <code className="text-xs">{webhookId || '—'}</code>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Webhook Token</span>
                  <span>{webhookToken ? '••••••••' : '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Geoapify Key</span>
                  <span>{geoapifyKey ? '••••••••' : '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">CTI Key</span>
                  <span>{ctiKey ? '••••••••' : '—'}</span>
                </div>
                {configTab === 'advanced' && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Config mode</span>
                    <span className="font-medium">Raw YAML</span>
                  </div>
                )}
              </div>
            </div>

            <div className="rounded-lg border p-4 space-y-3">
              <h4 className="font-medium text-sm">What will happen</h4>
              <ol className="space-y-2 text-sm text-muted-foreground list-decimal list-inside">
                <li>
                  A <code className="text-xs">discord.yaml</code> notification config will be{' '}
                  <strong className="text-foreground">written</strong> to the CrowdSec container
                </li>
                <li>
                  CrowdSec profiles will be{' '}
                  <strong className="text-foreground">updated</strong> to reference the Discord
                  notification plugin
                </li>
                <li>
                  Environment variables will be{' '}
                  <strong className="text-foreground">set</strong> in the compose configuration
                </li>
                <li>
                  CrowdSec container will be{' '}
                  <strong className="text-foreground">restarted</strong> to load the new
                  notification plugin
                </li>
                <li>
                  Setup will be <strong className="text-foreground">verified</strong> across all
                  components
                </li>
              </ol>
            </div>

            <Button
              className="w-full"
              onClick={() => saveMutation.mutate()}
              disabled={saveMutation.isPending}
            >
              {saveMutation.isPending ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Settings className="h-4 w-4 mr-2" />
                  Save &amp; Continue to Apply
                </>
              )}
            </Button>
          </div>
        ),
      },

      // ── Step 4: Apply ──────────────────────────────────────────────────────
      {
        id: 'apply',
        title: 'Apply',
        description: 'Applying configuration to your system',
        content: (
          <div className="space-y-4">
            {applySteps.length > 0 ? (
              <StepProgress steps={applySteps} />
            ) : (
              <div className="text-center py-8 space-y-4">
                <Rocket className="h-12 w-12 mx-auto text-muted-foreground" />
                <div>
                  <p className="font-medium">Ready to apply</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    This will write the discord.yaml config and restart the CrowdSec container.
                  </p>
                </div>
                <Button
                  onClick={() => applyMutation.mutate()}
                  disabled={applyMutation.isPending}
                >
                  {applyMutation.isPending ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Applying...
                    </>
                  ) : (
                    <>
                      <Rocket className="h-4 w-4 mr-2" />
                      Apply Now
                    </>
                  )}
                </Button>
              </div>
            )}
          </div>
        ),
      },

      // ── Step 5: Verify ─────────────────────────────────────────────────────
      {
        id: 'verify',
        title: 'Verify',
        description: 'Checking that everything is working',
        content: (
          <div className="space-y-4">
            {currentConfig ? (
              <div className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="flex items-center gap-3 rounded-lg border p-4">
                    {currentConfig.enabled ? (
                      <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-muted-foreground" />
                    )}
                    <div>
                      <p className="text-sm font-medium">Notifications Enabled</p>
                      <p className="text-xs text-muted-foreground">
                        {currentConfig.enabled ? 'Active' : 'Disabled'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 rounded-lg border p-4">
                    {currentConfig.webhook_id ? (
                      <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-destructive" />
                    )}
                    <div>
                      <p className="text-sm font-medium">Webhook Configured</p>
                      <p className="text-xs text-muted-foreground">
                        {currentConfig.webhook_id ? 'ID set' : 'Missing'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 rounded-lg border p-4">
                    {currentConfig.geoapify_key ? (
                      <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-muted-foreground" />
                    )}
                    <div>
                      <p className="text-sm font-medium">Geoapify Key</p>
                      <p className="text-xs text-muted-foreground">
                        {currentConfig.geoapify_key ? 'Configured' : 'Not set'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 rounded-lg border p-4">
                    {currentConfig.crowdsec_restarted ? (
                      <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-muted-foreground" />
                    )}
                    <div>
                      <p className="text-sm font-medium">CrowdSec Restarted</p>
                      <p className="text-xs text-muted-foreground">
                        {currentConfig.crowdsec_restarted
                          ? 'Plugin loaded'
                          : 'Restart may be needed'}
                      </p>
                    </div>
                  </div>
                </div>

                <Button
                  variant="outline"
                  onClick={() => {
                    void refetchConfig()
                    void redetect()
                  }}
                >
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Re-check Status
                </Button>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-muted-foreground">
                <RefreshCw className="h-4 w-4 animate-spin" />
                Checking status...
              </div>
            )}
          </div>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      detecting,
      detectError,
      detectErr,
      detection,
      enabled,
      webhookUrl,
      webhookId,
      webhookToken,
      geoapifyKey,
      ctiKey,
      rawYaml,
      configTab,
      canProceedConfigure,
      applySteps,
      currentConfig,
      saveMutation.isPending,
      applyMutation.isPending,
    ],
  )

  // Suppress unused variable warning — payload is constructed inline above
  void EMPTY_CONFIG

  return (
    <div className="space-y-6">
      <PageHeader
        title="Notifications"
        description="Configure Discord notifications for CrowdSec alerts"
        breadcrumbs="Configuration / Notifications"
      />

      <FeatureWizard
        title="Discord Setup"
        icon={<Bell className="h-6 w-6" />}
        steps={steps}
        currentStep={currentStep}
        onStepChange={setCurrentStep}
        isProcessing={isProcessing}
        completedSteps={completedSteps}
        errorSteps={errorSteps}
      />
    </div>
  )
}
