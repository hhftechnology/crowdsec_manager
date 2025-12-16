import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { ProxyTypeCard } from '@/components/proxy/ProxyTypeCard'
import { ProxyType, PROXY_TYPES } from '@/lib/proxy-types'
import { FeaturePreview } from './FeaturePreview'
import { ProxyConfigurationForm } from './ProxyConfigurationForm'
import { Settings, CheckCircle, AlertTriangle, Info } from 'lucide-react'

interface ProxySetupWizardProps {
  onComplete?: (config: ProxySetupConfig) => void
  initialProxy?: ProxyType
  className?: string
}

export interface ProxySetupConfig {
  proxyType: ProxyType
  containerName: string
  configPaths: Record<string, string>
  customSettings: Record<string, string>
  enabledFeatures: string[]
}

export function ProxySetupWizard({ 
  onComplete, 
  initialProxy = 'traefik',
  className 
}: ProxySetupWizardProps) {
  const [selectedProxy, setSelectedProxy] = useState<ProxyType>(initialProxy)
  const [step, setStep] = useState<'selection' | 'configuration' | 'review'>('selection')
  const [config, setConfig] = useState<Partial<ProxySetupConfig>>({
    proxyType: initialProxy
  })

  const handleProxySelect = (proxyType: ProxyType) => {
    setSelectedProxy(proxyType)
    setConfig(prev => ({ ...prev, proxyType }))
  }

  const handleConfigurationComplete = (configData: Partial<ProxySetupConfig>) => {
    setConfig(prev => ({ ...prev, ...configData }))
    setStep('review')
  }

  const handleComplete = () => {
    if (onComplete && config.proxyType) {
      onComplete({
        proxyType: config.proxyType,
        containerName: config.containerName || config.proxyType,
        configPaths: config.configPaths || {},
        customSettings: config.customSettings || {},
        enabledFeatures: config.enabledFeatures || []
      })
    }
  }

  const selectedProxyInfo = PROXY_TYPES.find(p => p.type === selectedProxy)

  return (
    <Card className={`w-full max-w-4xl mx-auto ${className}`}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Settings className="h-6 w-6" />
          Proxy Configuration Setup
        </CardTitle>
        <CardDescription>
          Select your reverse proxy type to configure CrowdSec Manager
        </CardDescription>
        
        {/* Progress Indicator */}
        <div className="flex items-center gap-2 mt-4">
          <div className={`flex items-center gap-2 ${step === 'selection' ? 'text-primary' : 'text-muted-foreground'}`}>
            <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
              step === 'selection' ? 'bg-primary text-primary-foreground' : 
              step === 'configuration' || step === 'review' ? 'bg-green-500 text-white' : 'bg-muted'
            }`}>
              {step === 'selection' ? '1' : <CheckCircle className="h-3 w-3" />}
            </div>
            <span className="text-sm font-medium">Select Proxy</span>
          </div>
          
          <Separator orientation="horizontal" className="flex-1" />
          
          <div className={`flex items-center gap-2 ${step === 'configuration' ? 'text-primary' : 'text-muted-foreground'}`}>
            <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
              step === 'configuration' ? 'bg-primary text-primary-foreground' : 
              step === 'review' ? 'bg-green-500 text-white' : 'bg-muted'
            }`}>
              {step === 'review' ? <CheckCircle className="h-3 w-3" /> : '2'}
            </div>
            <span className="text-sm font-medium">Configure</span>
          </div>
          
          <Separator orientation="horizontal" className="flex-1" />
          
          <div className={`flex items-center gap-2 ${step === 'review' ? 'text-primary' : 'text-muted-foreground'}`}>
            <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
              step === 'review' ? 'bg-primary text-primary-foreground' : 'bg-muted'
            }`}>
              3
            </div>
            <span className="text-sm font-medium">Review</span>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {step === 'selection' && (
          <>
            {/* Proxy Type Selection */}
            <div>
              <h3 className="text-lg font-semibold mb-4">Choose Your Reverse Proxy</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {PROXY_TYPES.map((proxy) => (
                  <ProxyTypeCard 
                    key={proxy.type}
                    proxy={proxy}
                    selected={selectedProxy === proxy.type}
                    onSelect={handleProxySelect}
                  />
                ))}
              </div>
            </div>

            {/* Feature Preview */}
            {selectedProxyInfo && (
              <>
                <Separator />
                <FeaturePreview proxyType={selectedProxy} />
              </>
            )}

            {/* Important Notes */}
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>
                <strong>Important:</strong> The proxy type cannot be changed after initial setup. 
                Choose carefully based on your infrastructure requirements.
              </AlertDescription>
            </Alert>

            {/* Continue Button */}
            <div className="flex justify-end">
              <Button 
                onClick={() => setStep('configuration')}
                disabled={!selectedProxy}
              >
                Continue to Configuration
              </Button>
            </div>
          </>
        )}

        {step === 'configuration' && (
          <>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">Configure {selectedProxyInfo?.name}</h3>
              <Badge variant="outline">
                {selectedProxyInfo?.name}
              </Badge>
            </div>
            
            <ProxyConfigurationForm 
              proxyType={selectedProxy}
              onComplete={handleConfigurationComplete}
              initialConfig={config}
            />
            
            <div className="flex justify-between">
              <Button 
                variant="outline"
                onClick={() => setStep('selection')}
              >
                Back to Selection
              </Button>
            </div>
          </>
        )}

        {step === 'review' && (
          <>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">Review Configuration</h3>
              <Badge variant="default">
                Ready to Deploy
              </Badge>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Proxy Details</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Type:</span>
                      <span className="text-sm font-medium">{selectedProxyInfo?.name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Container:</span>
                      <span className="text-sm font-medium">{config.containerName}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Features:</span>
                      <span className="text-sm font-medium">{selectedProxyInfo?.features.length}</span>
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Available Features</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-1">
                      {selectedProxyInfo?.features.map(feature => (
                        <Badge key={feature} variant="secondary" className="text-xs">
                          {feature}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
              
              {selectedProxyInfo?.experimental && (
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Experimental Proxy:</strong> {selectedProxyInfo.name} is marked as experimental. 
                    Some features may not be fully supported.
                  </AlertDescription>
                </Alert>
              )}
            </div>
            
            <div className="flex justify-between">
              <Button 
                variant="outline"
                onClick={() => setStep('configuration')}
              >
                Back to Configuration
              </Button>
              <Button onClick={handleComplete}>
                Complete Setup
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}