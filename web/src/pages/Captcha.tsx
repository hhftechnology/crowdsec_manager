import { useState, useMemo, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { captchaAPI } from '@/lib/api/captcha'
import { FeatureWizard, StepProgress, PageHeader, QueryError } from '@/components/common'
import type { WizardStep } from '@/components/common'
import type { StepResult, FeatureDetectionResult } from '@/lib/api/types'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  ScanFace,
  Settings,
  Rocket,
  CheckCircle,
  AlertCircle,
  RefreshCw,
  Info,
} from 'lucide-react'

const PROVIDER_OPTIONS = [
  { value: 'turnstile', label: 'Cloudflare Turnstile', url: 'https://dash.cloudflare.com/sign-up' },
  { value: 'recaptcha', label: 'Google reCAPTCHA', url: 'https://www.google.com/recaptcha/admin' },
  { value: 'hcaptcha', label: 'hCaptcha', url: 'https://dashboard.hcaptcha.com/signup' },
] as const

type ProviderValue = (typeof PROVIDER_OPTIONS)[number]['value']

interface CaptchaWizardInnerProps {
  detection: FeatureDetectionResult | undefined
  statusData: { configured: boolean; provider?: string; captchaHTMLExists: boolean; hasHTMLPath: boolean; implemented: boolean } | undefined
  detecting: boolean
  detectError: boolean
  detectErr: Error | null
  refetchStatus: () => void
  redetect: () => void
}

function CaptchaWizardInner({
  detection,
  statusData,
  detecting,
  detectError,
  detectErr,
  refetchStatus,
  redetect,
}: CaptchaWizardInnerProps) {
  const queryClient = useQueryClient()
  const [currentStep, setCurrentStep] = useState(0)
  const detectedVals = detection?.detected_values

  const [provider, setProvider] = useState<ProviderValue>(() => {
    const p = detectedVals?.provider as ProviderValue
    return PROVIDER_OPTIONS.some((o) => o.value === p) ? p : 'turnstile'
  })
  const [siteKey, setSiteKey] = useState(() =>
    typeof detectedVals?.site_key === 'string' ? detectedVals.site_key : ''
  )
  const [secretKey, setSecretKey] = useState(() =>
    typeof detectedVals?.secret_key === 'string' ? detectedVals.secret_key : ''
  )
  const [applySteps, setApplySteps] = useState<StepResult[]>([])
  const [retryingStep, setRetryingStep] = useState<number | undefined>()
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(() =>
    detectedVals && Object.keys(detectedVals).length > 0 ? new Set(['detect']) : new Set()
  )
  const [errorSteps, setErrorSteps] = useState<Set<string>>(new Set())

  // Save config mutation
  const saveMutation = useMutation({
    mutationFn: () =>
      captchaAPI.saveConfig({ provider, site_key: siteKey, secret_key: secretKey }),
    onSuccess: () => {
      toast.success('Configuration saved')
      setCompletedSteps((prev) => new Set([...prev, 'configure', 'review']))
      setCurrentStep(3)
    },
    onError: () => toast.error('Failed to save configuration'),
  })

  // Apply mutation
  const applyMutation = useMutation({
    mutationFn: () => captchaAPI.applyConfig(),
    onSuccess: (res) => {
      const data = res.data.data
      if (data?.steps) setApplySteps(data.steps)
      if (data?.applied) {
        toast.success('Captcha applied successfully!')
        setCompletedSteps((prev) => new Set([...prev, 'apply']))
        setCurrentStep(4)
      } else {
        toast.error('Some steps failed. Check details below.')
        setErrorSteps((prev) => new Set([...prev, 'apply']))
      }
      queryClient.invalidateQueries({ queryKey: ['captcha-status'] })
      queryClient.invalidateQueries({ queryKey: ['captcha-detect'] })
    },
    onError: () => toast.error('Failed to apply configuration'),
  })

  const handleRetryStep = useCallback(async (stepNum: number) => {
    setRetryingStep(stepNum)
    try {
      const res = await captchaAPI.applyConfig(stepNum)
      const data = res.data.data
      if (data?.steps) {
        setApplySteps((prev) =>
          prev.map((s) => {
            const updated = data.steps.find((u: StepResult) => u.step === s.step)
            return updated ?? s
          })
        )
        const retried = data.steps[0]
        if (retried?.success) {
          toast.success(`Step ${stepNum} succeeded`)
          setApplySteps((prev) => {
            const allOk = prev.every((s) => s.success || s.skipped)
            if (allOk) {
              setCompletedSteps((p) => new Set([...p, 'apply']))
              setErrorSteps((p) => {
                const n = new Set(p)
                n.delete('apply')
                return n
              })
            }
            return prev
          })
        } else {
          toast.error(`Step ${stepNum} failed: ${retried?.error || 'Unknown error'}`)
        }
      }
    } catch {
      toast.error(`Failed to retry step ${stepNum}`)
    } finally {
      setRetryingStep(undefined)
      queryClient.invalidateQueries({ queryKey: ['captcha-status'] })
      queryClient.invalidateQueries({ queryKey: ['captcha-detect'] })
    }
  }, [queryClient])

  const selectedProvider = PROVIDER_OPTIONS.find((p) => p.value === provider)
  const isProcessing = saveMutation.isPending || applyMutation.isPending || retryingStep !== undefined || detecting

  const steps: WizardStep[] = useMemo(
    () => [
      // ── Step 1: Detect ───────────────────────────────────────────────────────
      {
        id: 'detect',
        title: 'Detect',
        description: 'Scanning for existing captcha configuration',
        content: (
          <div className="space-y-4">
            {detecting ? (
              <div className="flex items-center gap-2 text-muted-foreground">
                <RefreshCw className="h-4 w-4 animate-spin" />
                Scanning configuration files...
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
                        {Boolean(detection.detected_values.provider) && (
                          <li>
                            Provider:{' '}
                            <strong>{String(detection.detected_values.provider)}</strong>
                          </li>
                        )}
                        {Boolean(detection.detected_values.site_key) && (
                          <li>
                            Site Key:{' '}
                            <code className="text-xs">
                              {String(detection.detected_values.site_key).substring(0, 12)}...
                            </code>
                          </li>
                        )}
                        {Boolean(detection.detected_values.html_exists) && (
                          <li>
                            HTML file:{' '}
                            <code className="text-xs">
                              {String(detection.detected_values.html_path)}
                            </code>
                          </li>
                        )}
                      </ul>
                      <p className="mt-2 text-xs text-muted-foreground">
                        These values are pre-filled in the next step.
                      </p>
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            ) : null}
          </div>
        ),
      },

      // ── Step 2: Configure ────────────────────────────────────────────────────
      {
        id: 'configure',
        title: 'Configure',
        description: 'Enter your captcha provider credentials',
        canProceed: siteKey.length > 0 && secretKey.length > 0,
        content: (
          <div className="space-y-6">
            {/* Provider selection */}
            <div className="space-y-2">
              <label className="text-sm font-medium">Captcha Provider</label>
              <div className="grid gap-3 sm:grid-cols-3">
                {PROVIDER_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setProvider(opt.value)}
                    className={[
                      'rounded-lg border-2 p-4 text-left transition-colors',
                      provider === opt.value
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:border-primary/50',
                    ].join(' ')}
                  >
                    <p className="font-medium text-sm">{opt.label}</p>
                    <a
                      href={opt.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline mt-1 inline-block"
                      onClick={(e) => e.stopPropagation()}
                    >
                      Get keys &rarr;
                    </a>
                  </button>
                ))}
              </div>
            </div>

            {/* Keys */}
            <div className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="site-key" className="text-sm font-medium">
                  Site Key (Public)
                </label>
                <Input
                  id="site-key"
                  placeholder="Enter your site key..."
                  value={siteKey}
                  onChange={(e) => setSiteKey(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="secret-key" className="text-sm font-medium">
                  Secret Key (Private)
                </label>
                <Input
                  id="secret-key"
                  type="password"
                  placeholder="Enter your secret key..."
                  value={secretKey}
                  onChange={(e) => setSecretKey(e.target.value)}
                />
              </div>
            </div>
          </div>
        ),
      },

      // ── Step 3: Review ───────────────────────────────────────────────────────
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
                  <span className="text-muted-foreground">Provider</span>
                  <span className="font-medium">{selectedProvider?.label}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Site Key</span>
                  <code className="text-xs">{siteKey.substring(0, 16)}...</code>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Secret Key</span>
                  <span>••••••••</span>
                </div>
              </div>
            </div>

            <div className="rounded-lg border p-4 space-y-3">
              <h4 className="font-medium text-sm">What will happen</h4>
              <ol className="space-y-2 text-sm text-muted-foreground list-decimal list-inside">
                <li>
                  A captcha HTML challenge page will be{' '}
                  <strong className="text-foreground">created</strong> in your Traefik config
                  directory
                </li>
                <li>
                  Traefik dynamic config will be{' '}
                  <strong className="text-foreground">updated</strong> with captcha middleware
                  settings
                </li>
                <li>
                  CrowdSec profiles will be{' '}
                  <strong className="text-foreground">updated</strong> to include captcha decisions
                </li>
                <li>
                  Traefik container will be{' '}
                  <strong className="text-foreground">restarted</strong> to load new config
                </li>
                <li>
                  CrowdSec container will be{' '}
                  <strong className="text-foreground">restarted</strong> to load new profiles
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

      // ── Step 4: Apply ────────────────────────────────────────────────────────
      {
        id: 'apply',
        title: 'Apply',
        description: 'Applying configuration to your system',
        content: (
          <div className="space-y-4">
            {applySteps.length > 0 ? (
              <StepProgress
                steps={applySteps}
                retryingStep={retryingStep}
                onRetryStep={handleRetryStep}
              />
            ) : (
              <div className="text-center py-8 space-y-4">
                <Rocket className="h-12 w-12 mx-auto text-muted-foreground" />
                <div>
                  <p className="font-medium">Ready to apply</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    This will write config files and restart containers.
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

      // ── Step 5: Verify ───────────────────────────────────────────────────────
      {
        id: 'verify',
        title: 'Verify',
        description: 'Checking that everything is working',
        content: (
          <div className="space-y-4">
            {statusData ? (
              <div className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="flex items-center gap-3 rounded-lg border p-4">
                    {statusData.configured ? (
                      <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-destructive" />
                    )}
                    <div>
                      <p className="text-sm font-medium">Provider Configured</p>
                      <p className="text-xs text-muted-foreground">
                        {statusData.provider ?? 'Not set'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 rounded-lg border p-4">
                    {statusData.captchaHTMLExists ? (
                      <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-destructive" />
                    )}
                    <div>
                      <p className="text-sm font-medium">HTML Challenge Page</p>
                      <p className="text-xs text-muted-foreground">
                        {statusData.captchaHTMLExists ? 'Exists' : 'Missing'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 rounded-lg border p-4">
                    {statusData.hasHTMLPath ? (
                      <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-destructive" />
                    )}
                    <div>
                      <p className="text-sm font-medium">Traefik Config</p>
                      <p className="text-xs text-muted-foreground">
                        {statusData.hasHTMLPath ? 'Configured' : 'Not configured'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 rounded-lg border p-4">
                    {statusData.implemented ? (
                      <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-destructive" />
                    )}
                    <div>
                      <p className="text-sm font-medium">Fully Implemented</p>
                      <p className="text-xs text-muted-foreground">
                        {statusData.implemented ? 'Active' : 'Incomplete'}
                      </p>
                    </div>
                  </div>
                </div>

                <Button
                  variant="outline"
                  onClick={() => {
                    void refetchStatus()
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
    [
      detecting,
      detectError,
      detectErr,
      detection,
      siteKey,
      secretKey,
      provider,
      selectedProvider,
      applySteps,
      statusData,
      saveMutation,
      applyMutation,
      handleRetryStep,
      redetect,
      refetchStatus,
      retryingStep,
    ],
  )

  return (
    <FeatureWizard
      title="Captcha Setup"
      icon={<ScanFace className="h-6 w-6" />}
      steps={steps}
      currentStep={currentStep}
      onStepChange={setCurrentStep}
      isProcessing={isProcessing}
      completedSteps={completedSteps}
      errorSteps={errorSteps}
    />
  )
}

export default function Captcha() {
  const {
    data: detection,
    isLoading: detecting,
    isError: detectError,
    error: detectErr,
    refetch: redetect,
  } = useQuery({
    queryKey: ['captcha-detect'],
    queryFn: async () => {
      const res = await captchaAPI.detect()
      return res.data.data as FeatureDetectionResult
    },
  })

  const { data: statusData, refetch: refetchStatus } = useQuery({
    queryKey: ['captcha-status'],
    queryFn: async () => {
      const res = await captchaAPI.getStatus()
      return res.data.data
    },
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="Captcha Protection"
        description="Configure captcha challenge pages for CrowdSec decisions"
        breadcrumbs="Security / Captcha"
      />

      <CaptchaWizardInner
        key={detection?.status ?? 'loading'}
        detection={detection}
        statusData={statusData}
        detecting={detecting}
        detectError={detectError}
        detectErr={detectErr as Error | null}
        refetchStatus={refetchStatus}
        redetect={redetect}
      />
    </div>
  )
}
