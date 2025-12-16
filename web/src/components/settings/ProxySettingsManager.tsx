import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ProxyType, PROXY_TYPES, Feature } from '@/lib/proxy-types'
import { ProxyHealthMonitor } from './ProxyHealthMonitor'
import { FeatureTogglePanel } from './FeatureTogglePanel'
import {
  Settings,
  Container,
  Folder,
  Network,
  Save,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Info
} from 'lucide-react'

interface ProxySettings {
  proxyType: ProxyType
  containerName: string
  configPaths: {
    dynamic: string
    static: string
    logs: string
  }
  customSettings: Record<string, string>
  enabledFeatures: Feature[]
  healthCheckEnabled: boolean
  metricsEnabled: boolean
  autoRestart: boolean
}

interface ProxySettingsManagerProps {
  currentSettings: ProxySettings
  onSettingsUpdate?: (settings: ProxySettings) => void
  className?: string
}

export function ProxySettingsManager({ 
  currentSettings, 
  onSettingsUpdate,
  className 
}: ProxySettingsManagerProps) {
  const [isEditing, setIsEditing] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [lastSaved, setLastSaved] = useState<Date | null>(null)

  const proxyInfo = PROXY_TYPES.find(p => p.type === currentSettings.proxyType)

  const { register, handleSubmit, watch, setValue, formState: { errors, isDirty } } = useForm<ProxySettings>({
    defaultValues: currentSettings,
    mode: 'onChange'
  })

  const watchedSettings = watch()

  const handleSave = async (data: ProxySettings) => {
    setIsSaving(true)
    
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      onSettingsUpdate?.(data)
      setLastSaved(new Date())
      setIsEditing(false)
    } catch (error) {
      console.error('Failed to save settings:', error)
    } finally {
      setIsSaving(false)
    }
  }

  const handleCancel = () => {
    setIsEditing(false)
    // Reset form to current settings
    Object.keys(currentSettings).forEach(key => {
      setValue(key as keyof ProxySettings, currentSettings[key as keyof ProxySettings])
    })
  }

  const handleFeatureToggle = (feature: Feature, enabled: boolean) => {
    const currentFeatures = watchedSettings.enabledFeatures || []
    const newFeatures = enabled 
      ? [...currentFeatures, feature]
      : currentFeatures.filter(f => f !== feature)
    
    setValue('enabledFeatures', newFeatures, { shouldDirty: true })
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Proxy Settings</h2>
          <p className="text-muted-foreground">
            Manage your {proxyInfo?.name} integration settings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="flex items-center gap-1">
            <Container className="h-3 w-3" />
            {proxyInfo?.name}
          </Badge>
          {lastSaved && (
            <span className="text-xs text-muted-foreground">
              Last saved: {lastSaved.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      <Tabs defaultValue="general" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="paths">Paths</TabsTrigger>
          <TabsTrigger value="features">Features</TabsTrigger>
          <TabsTrigger value="health">Health</TabsTrigger>
        </TabsList>

        <form onSubmit={handleSubmit(handleSave)}>
          {/* General Settings */}
          <TabsContent value="general" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  General Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Proxy Type (Read-only) */}
                <div className="space-y-2">
                  <Label>Proxy Type</Label>
                  <div className="flex items-center gap-2">
                    <Input 
                      value={proxyInfo?.name || currentSettings.proxyType}
                      disabled
                      className="bg-muted"
                    />
                    <Badge variant="secondary">Immutable</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Proxy type cannot be changed after initial setup
                  </p>
                </div>

                {/* Container Name */}
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
                    disabled={!isEditing}
                    className={!isEditing ? 'bg-muted' : ''}
                  />
                  {errors.containerName && (
                    <p className="text-sm text-red-500">{errors.containerName.message}</p>
                  )}
                </div>

                {/* System Settings */}
                <Separator />
                <div className="space-y-4">
                  <h4 className="font-medium">System Settings</h4>
                  
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Health Check</Label>
                      <p className="text-xs text-muted-foreground">
                        Monitor container health status
                      </p>
                    </div>
                    <Switch
                      {...register('healthCheckEnabled')}
                      disabled={!isEditing}
                    />
                  </div>

                  {currentSettings.proxyType === 'traefik' && (
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label>Metrics Collection</Label>
                        <p className="text-xs text-muted-foreground">
                          Enable Traefik metrics endpoint
                        </p>
                      </div>
                      <Switch
                        {...register('metricsEnabled')}
                        disabled={!isEditing}
                      />
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Auto Restart</Label>
                      <p className="text-xs text-muted-foreground">
                        Automatically restart container on failure
                      </p>
                    </div>
                    <Switch
                      {...register('autoRestart')}
                      disabled={!isEditing}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Path Configuration */}
          <TabsContent value="paths" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Folder className="h-5 w-5" />
                  Configuration Paths
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="dynamicPath">Dynamic Configuration Path</Label>
                  <Input
                    id="dynamicPath"
                    {...register('configPaths.dynamic')}
                    disabled={!isEditing}
                    className={!isEditing ? 'bg-muted' : ''}
                  />
                  <p className="text-xs text-muted-foreground">
                    Path to dynamic configuration file or directory
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="staticPath">Static Configuration Path</Label>
                  <Input
                    id="staticPath"
                    {...register('configPaths.static')}
                    disabled={!isEditing}
                    className={!isEditing ? 'bg-muted' : ''}
                  />
                  <p className="text-xs text-muted-foreground">
                    Path to main configuration file
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="logsPath">Logs Path</Label>
                  <Input
                    id="logsPath"
                    {...register('configPaths.logs')}
                    disabled={!isEditing}
                    className={!isEditing ? 'bg-muted' : ''}
                  />
                  <p className="text-xs text-muted-foreground">
                    Path to access logs directory
                  </p>
                </div>

                {/* Custom Settings */}
                <Separator />
                <div className="space-y-2">
                  <Label htmlFor="customSettings">Custom Settings (JSON)</Label>
                  <Textarea
                    id="customSettings"
                    {...register('customSettings', {
                      setValueAs: (value) => {
                        try {
                          return typeof value === 'string' ? JSON.parse(value) : value
                        } catch {
                          return value
                        }
                      }
                    })}
                    value={JSON.stringify(watchedSettings.customSettings || {}, null, 2)}
                    onChange={(e) => {
                      try {
                        const parsed = JSON.parse(e.target.value)
                        setValue('customSettings', parsed, { shouldDirty: true })
                      } catch {
                        // Invalid JSON, keep as string for now
                      }
                    }}
                    disabled={!isEditing}
                    className={`font-mono text-sm ${!isEditing ? 'bg-muted' : ''}`}
                    rows={6}
                  />
                  <p className="text-xs text-muted-foreground">
                    Additional proxy-specific settings in JSON format
                  </p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Feature Management */}
          <TabsContent value="features" className="space-y-6">
            <FeatureTogglePanel
              proxyType={currentSettings.proxyType}
              enabledFeatures={watchedSettings.enabledFeatures || []}
              onFeatureToggle={handleFeatureToggle}
              disabled={!isEditing}
            />
          </TabsContent>

          {/* Health Monitoring */}
          <TabsContent value="health" className="space-y-6">
            <ProxyHealthMonitor
              proxyType={currentSettings.proxyType}
              containerName={currentSettings.containerName}
              healthCheckEnabled={watchedSettings.healthCheckEnabled}
            />
          </TabsContent>

          {/* Action Buttons */}
          <div className="flex items-center justify-between pt-6 border-t">
            <div className="flex items-center gap-2">
              {isDirty && (
                <Alert className="w-auto">
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    You have unsaved changes
                  </AlertDescription>
                </Alert>
              )}
            </div>

            <div className="flex gap-2">
              {isEditing ? (
                <>
                  <Button 
                    type="button" 
                    variant="outline" 
                    onClick={handleCancel}
                    disabled={isSaving}
                  >
                    Cancel
                  </Button>
                  <Button 
                    type="submit" 
                    disabled={isSaving || !isDirty}
                    className="flex items-center gap-2"
                  >
                    {isSaving ? (
                      <RefreshCw className="h-4 w-4 animate-spin" />
                    ) : (
                      <Save className="h-4 w-4" />
                    )}
                    {isSaving ? 'Saving...' : 'Save Changes'}
                  </Button>
                </>
              ) : (
                <Button 
                  type="button" 
                  onClick={() => setIsEditing(true)}
                  className="flex items-center gap-2"
                >
                  <Settings className="h-4 w-4" />
                  Edit Settings
                </Button>
              )}
            </div>
          </div>
        </form>
      </Tabs>
    </div>
  )
}