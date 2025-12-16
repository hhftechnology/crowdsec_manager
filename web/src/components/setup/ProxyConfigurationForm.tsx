import { useState, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { ProxyType, PROXY_TYPES } from '@/lib/proxy-types'
import { ProxySetupConfig } from './ProxySetupWizard'
import {
  Settings,
  Folder,
  Container,
  AlertTriangle,
  Info,
  CheckCircle
} from 'lucide-react'

interface ProxyConfigurationFormProps {
  proxyType: ProxyType
  onComplete: (config: Partial<ProxySetupConfig>) => void
  initialConfig?: Partial<ProxySetupConfig>
  className?: string
}

interface FormData {
  containerName: string
  dynamicConfigPath: string
  staticConfigPath: string
  logsPath: string
  enableHealthCheck: boolean
  enableMetrics: boolean
  customSettings: string
}

const DEFAULT_CONFIGS: Record<ProxyType, Partial<FormData>> = {
  traefik: {
    containerName: 'traefik',
    dynamicConfigPath: '/etc/traefik/dynamic_config.yml',
    staticConfigPath: '/etc/traefik/traefik.yml',
    logsPath: '/var/log/traefik',
    enableHealthCheck: true,
    enableMetrics: true
  },
  nginx: {
    containerName: 'nginx-proxy-manager',
    dynamicConfigPath: '/data/nginx/proxy_host',
    staticConfigPath: '/data/nginx/nginx.conf',
    logsPath: '/data/logs',
    enableHealthCheck: true,
    enableMetrics: false
  },
  caddy: {
    containerName: 'caddy',
    dynamicConfigPath: '/etc/caddy/Caddyfile',
    staticConfigPath: '/etc/caddy/Caddyfile',
    logsPath: '/var/log/caddy',
    enableHealthCheck: true,
    enableMetrics: false
  },
  haproxy: {
    containerName: 'haproxy',
    dynamicConfigPath: '/usr/local/etc/haproxy/haproxy.cfg',
    staticConfigPath: '/usr/local/etc/haproxy/haproxy.cfg',
    logsPath: '/var/log/haproxy',
    enableHealthCheck: true,
    enableMetrics: false
  },
  zoraxy: {
    containerName: 'zoraxy',
    dynamicConfigPath: '/opt/zoraxy/config',
    staticConfigPath: '/opt/zoraxy/config',
    logsPath: '/opt/zoraxy/logs',
    enableHealthCheck: true,
    enableMetrics: false
  },
  standalone: {
    containerName: 'crowdsec-manager',
    dynamicConfigPath: '',
    staticConfigPath: '',
    logsPath: '/var/log/crowdsec',
    enableHealthCheck: true,
    enableMetrics: true
  }
}

export function ProxyConfigurationForm({ 
  proxyType, 
  onComplete, 
  initialConfig,
  className 
}: ProxyConfigurationFormProps) {
  const proxyInfo = PROXY_TYPES.find(p => p.type === proxyType)
  const defaultConfig = DEFAULT_CONFIGS[proxyType]
  
  const { register, handleSubmit, watch, setValue, formState: { errors, isValid } } = useForm<FormData>({
    defaultValues: {
      ...defaultConfig,
      customSettings: initialConfig?.customSettings ? 
        JSON.stringify(initialConfig.customSettings, null, 2) : 
        '{}'
    },
    mode: 'onChange'
  })

  const [isAdvancedMode, setIsAdvancedMode] = useState(false)

  // Watch form values for real-time validation
  const containerName = watch('containerName')
  const enableHealthCheck = watch('enableHealthCheck')

  const onSubmit = (data: FormData) => {
    try {
      const customSettings = data.customSettings ? JSON.parse(data.customSettings) : {}
      
      const config: Partial<ProxySetupConfig> = {
        proxyType,
        containerName: data.containerName,
        configPaths: {
          dynamic: data.dynamicConfigPath,
          static: data.staticConfigPath,
          logs: data.logsPath
        },
        customSettings,
        enabledFeatures: [
          ...(data.enableHealthCheck ? ['health'] : []),
          ...(data.enableMetrics ? ['metrics'] : []),
          ...(proxyInfo?.features || [])
        ]
      }
      
      onComplete(config)
    } catch (error) {
      console.error('Invalid JSON in custom settings:', error)
    }
  }

  const getConfigurationHelp = () => {
    switch (proxyType) {
      case 'traefik':
        return 'Traefik uses dynamic configuration files for routing rules and static configuration for global settings.'
      case 'nginx':
        return 'Nginx Proxy Manager stores configuration in the data directory. Logs are automatically parsed from the standard location.'
      case 'caddy':
        return 'Caddy uses a single Caddyfile for configuration. Automatic HTTPS is enabled by default.'
      case 'haproxy':
        return 'HAProxy uses a single configuration file. SPOA bouncer integration requires additional setup.'
      case 'zoraxy':
        return 'Zoraxy is experimental. Configuration paths may vary depending on your setup.'
      case 'standalone':
        return 'Standalone mode runs CrowdSec without proxy integration. Only core CrowdSec features are available.'
      default:
        return 'Configure the paths and settings for your proxy type.'
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className={className}>
      <div className="space-y-6">
        {/* Basic Configuration */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Container className="h-4 w-4" />
              Basic Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="containerName">Container Name</Label>
              <Input
                id="containerName"
                {...register('containerName', { 
                  required: 'Container name is required',
                  pattern: {
                    value: /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/,
                    message: 'Invalid container name format'
                  }
                })}
                placeholder={defaultConfig.containerName}
              />
              {errors.containerName && (
                <p className="text-sm text-red-500">{errors.containerName.message}</p>
              )}
              <p className="text-xs text-muted-foreground">
                The Docker container name for your {proxyInfo?.name} instance
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <Switch
                id="enableHealthCheck"
                {...register('enableHealthCheck')}
              />
              <Label htmlFor="enableHealthCheck" className="text-sm">
                Enable health monitoring
              </Label>
            </div>

            {proxyType === 'traefik' && (
              <div className="flex items-center space-x-2">
                <Switch
                  id="enableMetrics"
                  {...register('enableMetrics')}
                />
                <Label htmlFor="enableMetrics" className="text-sm">
                  Enable metrics collection
                </Label>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Path Configuration */}
        {proxyType !== 'standalone' && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Folder className="h-4 w-4" />
                Path Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="dynamicConfigPath">Dynamic Configuration Path</Label>
                <Input
                  id="dynamicConfigPath"
                  {...register('dynamicConfigPath')}
                  placeholder={defaultConfig.dynamicConfigPath}
                />
                <p className="text-xs text-muted-foreground">
                  Path to dynamic configuration file or directory
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="staticConfigPath">Static Configuration Path</Label>
                <Input
                  id="staticConfigPath"
                  {...register('staticConfigPath')}
                  placeholder={defaultConfig.staticConfigPath}
                />
                <p className="text-xs text-muted-foreground">
                  Path to main configuration file
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="logsPath">Logs Path</Label>
                <Input
                  id="logsPath"
                  {...register('logsPath')}
                  placeholder={defaultConfig.logsPath}
                />
                <p className="text-xs text-muted-foreground">
                  Path to access logs directory
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Advanced Configuration */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Settings className="h-4 w-4" />
              Advanced Configuration
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setIsAdvancedMode(!isAdvancedMode)}
              >
                {isAdvancedMode ? 'Hide' : 'Show'}
              </Button>
            </CardTitle>
          </CardHeader>
          {isAdvancedMode && (
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="customSettings">Custom Settings (JSON)</Label>
                <Textarea
                  id="customSettings"
                  {...register('customSettings', {
                    validate: (value) => {
                      if (!value || value.trim() === '') return true
                      try {
                        JSON.parse(value)
                        return true
                      } catch {
                        return 'Invalid JSON format'
                      }
                    }
                  })}
                  placeholder='{"key": "value"}'
                  rows={4}
                  className="font-mono text-sm"
                />
                {errors.customSettings && (
                  <p className="text-sm text-red-500">{errors.customSettings.message}</p>
                )}
                <p className="text-xs text-muted-foreground">
                  Additional proxy-specific settings in JSON format
                </p>
              </div>
            </CardContent>
          )}
        </Card>

        {/* Configuration Help */}
        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>
            <strong>{proxyInfo?.name} Configuration:</strong> {getConfigurationHelp()}
          </AlertDescription>
        </Alert>

        {/* Warnings */}
        {proxyInfo?.experimental && (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              <strong>Experimental Proxy:</strong> This proxy type is experimental. 
              Configuration options may change and some features may not work as expected.
            </AlertDescription>
          </Alert>
        )}

        {/* Submit Button */}
        <div className="flex justify-end">
          <Button 
            type="submit" 
            disabled={!isValid}
            className="flex items-center gap-2"
          >
            <CheckCircle className="h-4 w-4" />
            Continue to Review
          </Button>
        </div>
      </div>
    </form>
  )
}