import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { MigrationStatus, createTraefikMigrationData } from './MigrationStatus'
import { OnboardingTour } from './OnboardingTour'
import { ProxyType } from '@/lib/proxy-types'
import {
  Database,
  AlertTriangle,
  CheckCircle,
  ArrowRight,
  RefreshCw,
  Shield,
  Info
} from 'lucide-react'

interface MigrationWizardProps {
  detectedLegacyConfig?: {
    type: 'traefik'
    version: string
    configFiles: string[]
    hasData: boolean
  }
  onMigrationComplete?: (newProxyType: ProxyType) => void
  onSkipMigration?: () => void
  className?: string
}

type MigrationPhase = 'detection' | 'confirmation' | 'migration' | 'completion' | 'onboarding'

export function MigrationWizard({ 
  detectedLegacyConfig,
  onMigrationComplete,
  onSkipMigration,
  className 
}: MigrationWizardProps) {
  const [phase, setPhase] = useState<MigrationPhase>('detection')
  const [migrationData, setMigrationData] = useState(createTraefikMigrationData())
  const [isProcessing, setIsProcessing] = useState(false)

  useEffect(() => {
    if (detectedLegacyConfig) {
      setPhase('confirmation')
    }
  }, [detectedLegacyConfig])

  const handleStartMigration = async () => {
    setPhase('migration')
    setIsProcessing(true)

    // Simulate migration process
    const steps = migrationData.migrationSteps
    
    for (let i = 0; i < steps.length; i++) {
      // Update step to in-progress
      setMigrationData(prev => ({
        ...prev,
        migrationSteps: prev.migrationSteps.map((step, index) => 
          index === i ? { ...step, status: 'in-progress' } : step
        )
      }))

      // Simulate processing time
      await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000))

      // Update step to completed
      setMigrationData(prev => ({
        ...prev,
        migrationSteps: prev.migrationSteps.map((step, index) => 
          index === i ? { ...step, status: 'completed' } : step
        )
      }))
    }

    setIsProcessing(false)
    setPhase('completion')
  }

  const handleMigrationComplete = () => {
    setPhase('onboarding')
    onMigrationComplete?.('traefik')
  }

  const handleSkipMigration = () => {
    onSkipMigration?.()
  }

  const handleOnboardingComplete = () => {
    // Migration and onboarding complete
    console.log('Migration and onboarding completed')
  }

  if (phase === 'detection' && !detectedLegacyConfig) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Checking for Existing Configuration
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3">
            <RefreshCw className="h-4 w-4 animate-spin" />
            <span className="text-sm">Scanning for existing Traefik configuration...</span>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (phase === 'confirmation' && detectedLegacyConfig) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-orange-500" />
            Legacy Configuration Detected
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <Alert>
            <Info className="h-4 w-4" />
            <AlertTitle>Traefik Configuration Found</AlertTitle>
            <AlertDescription>
              We've detected an existing Traefik v{detectedLegacyConfig.version} configuration. 
              We can automatically migrate your settings to the new multi-proxy system while 
              maintaining full backward compatibility.
            </AlertDescription>
          </Alert>

          <div className="space-y-4">
            <h4 className="font-medium">What will be migrated:</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>Traefik configuration files</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>Environment variables</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>Database settings</span>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>Whitelist configurations</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>Captcha settings</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>API compatibility</span>
                </div>
              </div>
            </div>
          </div>

          <Alert>
            <Shield className="h-4 w-4" />
            <AlertDescription>
              <strong>Safe Migration:</strong> A complete backup will be created before migration. 
              You can rollback at any time if needed.
            </AlertDescription>
          </Alert>

          <div className="flex justify-between">
            <Button variant="outline" onClick={handleSkipMigration}>
              Skip Migration
            </Button>
            <Button onClick={handleStartMigration} className="flex items-center gap-2">
              Start Migration
              <ArrowRight className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (phase === 'migration') {
    return (
      <div className={className}>
        <MigrationStatus 
          migrationData={migrationData}
          onContinue={handleMigrationComplete}
        />
      </div>
    )
  }

  if (phase === 'completion') {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CheckCircle className="h-5 w-5 text-green-500" />
            Migration Completed Successfully
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <Alert className="border-green-200 bg-green-50">
            <CheckCircle className="h-4 w-4 text-green-600" />
            <AlertTitle className="text-green-800">Migration Successful</AlertTitle>
            <AlertDescription className="text-green-700">
              Your Traefik configuration has been successfully migrated to the new multi-proxy system. 
              All your settings, whitelists, and configurations have been preserved.
            </AlertDescription>
          </Alert>

          <div className="space-y-4">
            <h4 className="font-medium">What's New:</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <Badge variant="secondary" className="text-xs">New</Badge>
                  <span>Generic proxy terminology</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Badge variant="secondary" className="text-xs">New</Badge>
                  <span>Multi-proxy support ready</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Badge variant="secondary" className="text-xs">New</Badge>
                  <span>Enhanced UI components</span>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <Badge variant="outline" className="text-xs">Maintained</Badge>
                  <span>All Traefik features</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Badge variant="outline" className="text-xs">Maintained</Badge>
                  <span>API compatibility</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Badge variant="outline" className="text-xs">Maintained</Badge>
                  <span>Existing configurations</span>
                </div>
              </div>
            </div>
          </div>

          <div className="flex justify-end">
            <Button onClick={handleMigrationComplete} className="flex items-center gap-2">
              Continue to Dashboard
              <ArrowRight className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (phase === 'onboarding') {
    return (
      <div className={className}>
        <OnboardingTour 
          proxyType="traefik"
          onComplete={handleOnboardingComplete}
          onSkip={handleOnboardingComplete}
        />
      </div>
    )
  }

  return null
}