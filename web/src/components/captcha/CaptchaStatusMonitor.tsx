import { ProxyType } from '@/lib/proxy-types'
import { CaptchaStatus } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Progress } from '@/components/ui/progress'
import { 
  Activity, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  RefreshCw, 
  Shield, 
  FileText, 
  Settings,
  Info,
  Clock
} from 'lucide-react'

interface CaptchaStatusMonitorProps {
  status?: CaptchaStatus
  isLoading: boolean
  onRefresh: () => void
  proxyType: ProxyType
}

export function CaptchaStatusMonitor({ 
  status, 
  isLoading, 
  onRefresh, 
  proxyType 
}: CaptchaStatusMonitorProps) {
  const getOverallStatus = (): { status: 'healthy' | 'warning' | 'error'; message: string; progress: number } => {
    if (!status) {
      return { status: 'error', message: 'Unable to load status', progress: 0 }
    }

    let progress = 0
    const checks = [
      status.configSaved,
      status.configured,
      status.captchaHTMLExists,
      status.hasHTMLPath,
      status.implemented
    ]
    
    progress = (checks.filter(Boolean).length / checks.length) * 100

    if (status.implemented) {
      return { status: 'healthy', message: 'Captcha fully configured and operational', progress: 100 }
    }

    if (status.configured && status.captchaHTMLExists) {
      return { status: 'warning', message: 'Captcha configured but may need verification', progress }
    }

    if (status.configured || status.configSaved) {
      return { status: 'warning', message: 'Captcha partially configured', progress }
    }

    return { status: 'error', message: 'Captcha not configured', progress }
  }

  const overallStatus = getOverallStatus()

  const getStatusIcon = (condition: boolean) => {
    return condition ? (
      <CheckCircle className="h-4 w-4 text-green-500" />
    ) : (
      <XCircle className="h-4 w-4 text-red-500" />
    )
  }

  const getStatusBadge = (condition: boolean, trueText: string = 'Active', falseText: string = 'Inactive') => {
    return condition ? (
      <Badge variant="default" className="bg-green-100 text-green-800 border-green-200">
        {trueText}
      </Badge>
    ) : (
      <Badge variant="secondary" className="bg-red-100 text-red-600 border-red-200">
        {falseText}
      </Badge>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Captcha Status Monitor
            </CardTitle>
            <CardDescription>
              Real-time status of your captcha configuration
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={onRefresh}
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Overall Status */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="font-medium">Overall Status</h4>
            <div className="flex items-center gap-2">
              {overallStatus.status === 'healthy' && <CheckCircle className="h-4 w-4 text-green-500" />}
              {overallStatus.status === 'warning' && <AlertTriangle className="h-4 w-4 text-yellow-500" />}
              {overallStatus.status === 'error' && <XCircle className="h-4 w-4 text-red-500" />}
              <Badge 
                variant={overallStatus.status === 'healthy' ? 'default' : 'secondary'}
                className={
                  overallStatus.status === 'healthy' 
                    ? 'bg-green-100 text-green-800 border-green-200'
                    : overallStatus.status === 'warning'
                    ? 'bg-yellow-100 text-yellow-800 border-yellow-200'
                    : 'bg-red-100 text-red-600 border-red-200'
                }
              >
                {overallStatus.status === 'healthy' ? 'Operational' : 
                 overallStatus.status === 'warning' ? 'Partial' : 'Not Configured'}
              </Badge>
            </div>
          </div>
          
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span>{overallStatus.message}</span>
              <span>{Math.round(overallStatus.progress)}%</span>
            </div>
            <Progress value={overallStatus.progress} className="h-2" />
          </div>
        </div>

        {/* Detailed Status Checks */}
        {status && (
          <div className="space-y-4">
            <h4 className="font-medium">Configuration Checks</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center gap-2">
                    <Settings className="h-4 w-4" />
                    <span className="text-sm">Configuration Saved</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(status.configSaved)}
                    {getStatusBadge(status.configSaved, 'Saved', 'Not Saved')}
                  </div>
                </div>

                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4" />
                    <span className="text-sm">Middleware Configured</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(status.configured)}
                    {getStatusBadge(status.configured, 'Configured', 'Not Configured')}
                  </div>
                </div>

                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    <span className="text-sm">Captcha HTML Exists</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(status.captchaHTMLExists)}
                    {getStatusBadge(status.captchaHTMLExists, 'Exists', 'Missing')}
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    <span className="text-sm">HTML Path Configured</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(status.hasHTMLPath)}
                    {getStatusBadge(status.hasHTMLPath, 'Configured', 'Not Set')}
                  </div>
                </div>

                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4" />
                    <span className="text-sm">Fully Implemented</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(status.implemented)}
                    {getStatusBadge(status.implemented, 'Complete', 'Incomplete')}
                  </div>
                </div>

                {status.manually_configured && (
                  <div className="flex items-center justify-between p-3 border rounded-lg bg-blue-50">
                    <div className="flex items-center gap-2">
                      <Info className="h-4 w-4 text-blue-500" />
                      <span className="text-sm">Manual Configuration</span>
                    </div>
                    <Badge variant="outline" className="text-blue-600 border-blue-200">
                      Detected
                    </Badge>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Provider Information */}
        {status?.provider && (
          <div className="space-y-3">
            <h4 className="font-medium">Provider Information</h4>
            <div className="p-4 border rounded-lg bg-muted/50">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="font-medium">Current Provider:</span>
                  <p className="text-muted-foreground capitalize">{status.provider}</p>
                </div>
                {status.detectedProvider && status.detectedProvider !== status.provider && (
                  <div>
                    <span className="font-medium">Detected Provider:</span>
                    <p className="text-muted-foreground capitalize">{status.detectedProvider}</p>
                  </div>
                )}
                {status.savedProvider && status.savedProvider !== status.provider && (
                  <div>
                    <span className="font-medium">Saved Provider:</span>
                    <p className="text-muted-foreground capitalize">{status.savedProvider}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Status Alerts */}
        <div className="space-y-3">
          {!status?.implemented && status?.configured && (
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                Captcha middleware is configured but not fully operational. 
                Check that the captcha HTML file exists and is accessible.
              </AlertDescription>
            </Alert>
          )}

          {status?.configSaved && !status?.configured && (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>
                Captcha configuration is saved but not applied to the middleware. 
                The configuration may need to be reloaded.
              </AlertDescription>
            </Alert>
          )}

          {!status?.configSaved && !status?.configured && (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>
                Captcha is not configured. Use the Setup tab to configure your captcha provider and keys.
              </AlertDescription>
            </Alert>
          )}

          {status?.implemented && (
            <Alert>
              <CheckCircle className="h-4 w-4" />
              <AlertDescription>
                Captcha protection is fully operational and protecting your {proxyType} endpoints.
              </AlertDescription>
            </Alert>
          )}
        </div>

        {/* Last Updated */}
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Clock className="h-3 w-3" />
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </CardContent>
    </Card>
  )
}