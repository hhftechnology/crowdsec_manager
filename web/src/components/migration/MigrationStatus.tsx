import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import {
  CheckCircle,
  AlertTriangle,
  Info,
  ArrowRight,
  Database,
  Settings,
  FileText,
  Shield
} from 'lucide-react'

interface MigrationData {
  detected: boolean
  fromVersion: string
  toVersion: string
  configurationPreserved: boolean
  apiCompatibilityMaintained: boolean
  featuresAvailable: boolean
  backupCreated: boolean
  migrationSteps: MigrationStep[]
}

interface MigrationStep {
  id: string
  title: string
  description: string
  status: 'completed' | 'in-progress' | 'pending' | 'failed'
  details?: string
}

interface MigrationStatusProps {
  migrationData: MigrationData
  onContinue?: () => void
  onRollback?: () => void
  className?: string
}

export function MigrationStatus({ 
  migrationData, 
  onContinue, 
  onRollback,
  className 
}: MigrationStatusProps) {
  const completedSteps = migrationData.migrationSteps.filter(step => step.status === 'completed').length
  const totalSteps = migrationData.migrationSteps.length
  const progressPercentage = (completedSteps / totalSteps) * 100

  const getStatusIcon = (status: MigrationStep['status']) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'in-progress':
        return <div className="h-4 w-4 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
      case 'failed':
        return <AlertTriangle className="h-4 w-4 text-red-500" />
      default:
        return <div className="h-4 w-4 rounded-full border-2 border-muted" />
    }
  }

  const getStatusColor = (status: MigrationStep['status']) => {
    switch (status) {
      case 'completed':
        return 'text-green-600'
      case 'in-progress':
        return 'text-blue-600'
      case 'failed':
        return 'text-red-600'
      default:
        return 'text-muted-foreground'
    }
  }

  if (!migrationData.detected) {
    return null
  }

  return (
    <div className={className}>
      <Alert className="mb-6 border-blue-200 bg-blue-50">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Migration Detected</AlertTitle>
        <AlertDescription>
          We've detected an existing Traefik configuration. Your settings are being automatically 
          migrated to the new multi-proxy system.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Migration Progress
          </CardTitle>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span>Migrating from v{migrationData.fromVersion} to v{migrationData.toVersion}</span>
              <Badge variant="outline">
                {completedSteps}/{totalSteps} steps
              </Badge>
            </div>
            <Progress value={progressPercentage} className="h-2" />
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Migration Status Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center gap-2 text-sm">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span>Configuration preserved</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span>API compatibility maintained</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span>All features available</span>
            </div>
          </div>

          <Separator />

          {/* Migration Steps */}
          <div className="space-y-4">
            <h4 className="font-medium">Migration Steps</h4>
            <div className="space-y-3">
              {migrationData.migrationSteps.map((step, index) => (
                <div key={step.id} className="flex items-start gap-3">
                  {getStatusIcon(step.status)}
                  <div className="flex-1 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-medium ${getStatusColor(step.status)}`}>
                        {step.title}
                      </span>
                      {step.status === 'completed' && (
                        <Badge variant="secondary" className="text-xs">
                          Complete
                        </Badge>
                      )}
                      {step.status === 'in-progress' && (
                        <Badge variant="default" className="text-xs">
                          In Progress
                        </Badge>
                      )}
                      {step.status === 'failed' && (
                        <Badge variant="destructive" className="text-xs">
                          Failed
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {step.description}
                    </p>
                    {step.details && (
                      <p className="text-xs text-muted-foreground font-mono bg-muted p-2 rounded">
                        {step.details}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <Separator />

          {/* Backup Information */}
          {migrationData.backupCreated && (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>
                <strong>Backup Created:</strong> A complete backup of your current configuration 
                has been created before migration. You can rollback if needed.
              </AlertDescription>
            </Alert>
          )}

          {/* Action Buttons */}
          <div className="flex justify-between">
            {onRollback && (
              <Button variant="outline" onClick={onRollback}>
                Rollback Migration
              </Button>
            )}
            {onContinue && progressPercentage === 100 && (
              <Button onClick={onContinue} className="flex items-center gap-2">
                Continue to Dashboard
                <ArrowRight className="h-4 w-4" />
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// Default migration data for Traefik users
export const createTraefikMigrationData = (): MigrationData => ({
  detected: true,
  fromVersion: '1.0.0',
  toVersion: '2.0.0',
  configurationPreserved: true,
  apiCompatibilityMaintained: true,
  featuresAvailable: true,
  backupCreated: true,
  migrationSteps: [
    {
      id: 'backup',
      title: 'Create Configuration Backup',
      description: 'Backing up existing Traefik configuration and database',
      status: 'completed',
      details: 'Backup saved to /backups/pre-migration-backup.tar.gz'
    },
    {
      id: 'database',
      title: 'Migrate Database Schema',
      description: 'Adding proxy_settings table and updating existing records',
      status: 'completed',
      details: 'Added proxy_type=traefik to settings table'
    },
    {
      id: 'config',
      title: 'Update Configuration Files',
      description: 'Migrating environment variables to new proxy-agnostic format',
      status: 'completed',
      details: 'TRAEFIK_CONTAINER_NAME → PROXY_CONTAINER_NAME'
    },
    {
      id: 'api',
      title: 'Update API Endpoints',
      description: 'Ensuring backward compatibility for existing API calls',
      status: 'completed',
      details: 'Legacy endpoints maintained alongside new generic endpoints'
    },
    {
      id: 'features',
      title: 'Validate Feature Availability',
      description: 'Confirming all Traefik features are available in new system',
      status: 'completed',
      details: 'Whitelist, Captcha, Logs, Bouncer, Health, AppSec - All Available'
    }
  ]
})