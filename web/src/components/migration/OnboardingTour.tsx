import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { ProxyType, PROXY_TYPES } from '@/lib/proxy-types'
import {
  Lightbulb,
  ArrowRight,
  ArrowLeft,
  CheckCircle,
  Play,
  X,
  Shield,
  Activity,
  ListFilter,
  ScanFace,
  FileText,
  HeartPulse,
  Settings
} from 'lucide-react'

interface OnboardingStep {
  id: string
  title: string
  description: string
  icon: any
  action?: {
    label: string
    href?: string
    onClick?: () => void
  }
}

interface OnboardingTourProps {
  proxyType: ProxyType
  onComplete?: () => void
  onSkip?: () => void
  className?: string
}

const getOnboardingSteps = (proxyType: ProxyType): OnboardingStep[] => {
  const proxyInfo = PROXY_TYPES.find(p => p.type === proxyType)
  const proxyName = proxyInfo?.name || proxyType
  const supportedFeatures = proxyInfo?.features || []

  const steps: OnboardingStep[] = [
    {
      id: 'welcome',
      title: `Welcome to ${proxyName} Mode`,
      description: `Your CrowdSec Manager is now configured to work with ${proxyName}. Let's explore what you can do.`,
      icon: Shield,
      action: {
        label: 'Get Started',
        href: '/dashboard'
      }
    },
    {
      id: 'health',
      title: 'Monitor System Health',
      description: `Check the health of your ${proxyName} container and CrowdSec engine to ensure everything is running smoothly.`,
      icon: HeartPulse,
      action: {
        label: 'Check Health',
        href: '/health'
      }
    },
    {
      id: 'security',
      title: 'Review Security Decisions',
      description: 'View active security decisions and alerts to understand what threats CrowdSec is protecting you from.',
      icon: Activity,
      action: {
        label: 'View Decisions',
        href: '/decisions'
      }
    }
  ]

  // Add proxy-specific steps based on supported features
  if (supportedFeatures.includes('whitelist')) {
    steps.push({
      id: 'whitelist',
      title: 'Manage IP Whitelists',
      description: `Configure IP whitelists at the ${proxyName} level to allow trusted traffic to bypass security checks.`,
      icon: ListFilter,
      action: {
        label: 'Manage Whitelist',
        href: '/proxy-whitelist'
      }
    })
  }

  if (supportedFeatures.includes('captcha')) {
    steps.push({
      id: 'captcha',
      title: 'Set Up Captcha Protection',
      description: `Configure captcha middleware in ${proxyName} to add an extra layer of protection against automated attacks.`,
      icon: ScanFace,
      action: {
        label: 'Configure Captcha',
        href: '/captcha'
      }
    })
  }

  if (supportedFeatures.includes('logs')) {
    steps.push({
      id: 'logs',
      title: 'Analyze Access Logs',
      description: `View and analyze ${proxyName} access logs to understand traffic patterns and identify potential threats.`,
      icon: FileText,
      action: {
        label: 'View Logs',
        href: '/proxy-logs'
      }
    })
  }

  // Add configuration step
  steps.push({
    id: 'settings',
    title: 'Customize Your Setup',
    description: `Fine-tune your ${proxyName} integration settings and configure notifications to match your preferences.`,
    icon: Settings,
    action: {
      label: 'Open Settings',
      href: '/proxy-settings'
    }
  })

  return steps
}

export function OnboardingTour({ 
  proxyType, 
  onComplete, 
  onSkip,
  className 
}: OnboardingTourProps) {
  const [currentStep, setCurrentStep] = useState(0)
  const [isStarted, setIsStarted] = useState(false)
  
  const steps = getOnboardingSteps(proxyType)
  const proxyInfo = PROXY_TYPES.find(p => p.type === proxyType)
  
  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1)
    } else {
      handleComplete()
    }
  }

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1)
    }
  }

  const handleComplete = () => {
    onComplete?.()
  }

  const handleSkip = () => {
    onSkip?.()
  }

  const handleStart = () => {
    setIsStarted(true)
  }

  if (!isStarted) {
    return (
      <Card className={`border-primary ${className}`}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lightbulb className="h-5 w-5" />
            Welcome to {proxyInfo?.name} Mode
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Your CrowdSec Manager is now configured for {proxyInfo?.name}. 
              Take a quick tour to learn about the features available to you.
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-2">
                <h4 className="text-sm font-medium">What you'll learn:</h4>
                <ul className="text-xs text-muted-foreground space-y-1">
                  <li>• How to monitor system health</li>
                  <li>• Managing security decisions</li>
                  {proxyInfo?.features.includes('whitelist') && <li>• Setting up IP whitelists</li>}
                  {proxyInfo?.features.includes('captcha') && <li>• Configuring captcha protection</li>}
                  {proxyInfo?.features.includes('logs') && <li>• Analyzing access logs</li>}
                  <li>• Customizing your setup</li>
                </ul>
              </div>
              
              <div className="space-y-2">
                <h4 className="text-sm font-medium">Available Features:</h4>
                <div className="flex flex-wrap gap-1">
                  {proxyInfo?.features.map(feature => (
                    <Badge key={feature} variant="secondary" className="text-xs">
                      {feature}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
            
            <div className="flex justify-between">
              <Button variant="outline" onClick={handleSkip}>
                Skip Tour
              </Button>
              <Button onClick={handleStart} className="flex items-center gap-2">
                <Play className="h-4 w-4" />
                Start Tour
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  const currentStepData = steps[currentStep]
  const Icon = currentStepData.icon

  return (
    <Card className={`border-primary ${className}`}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Icon className="h-5 w-5" />
            {currentStepData.title}
          </CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs">
              Step {currentStep + 1} of {steps.length}
            </Badge>
            <Button variant="ghost" size="sm" onClick={handleSkip}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>
        
        {/* Progress indicator */}
        <div className="flex gap-1 mt-2">
          {steps.map((_, index) => (
            <div
              key={index}
              className={`h-1 flex-1 rounded ${
                index <= currentStep ? 'bg-primary' : 'bg-muted'
              }`}
            />
          ))}
        </div>
      </CardHeader>
      
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          {currentStepData.description}
        </p>
        
        {currentStepData.action && (
          <Alert>
            <CheckCircle className="h-4 w-4" />
            <AlertDescription>
              <strong>Try it now:</strong> {currentStepData.action.label} to explore this feature.
            </AlertDescription>
          </Alert>
        )}
        
        <Separator />
        
        <div className="flex justify-between">
          <Button 
            variant="outline" 
            onClick={handlePrevious}
            disabled={currentStep === 0}
            className="flex items-center gap-2"
          >
            <ArrowLeft className="h-4 w-4" />
            Previous
          </Button>
          
          <div className="flex gap-2">
            {currentStepData.action && (
              <Button 
                variant="outline"
                onClick={() => {
                  if (currentStepData.action?.href) {
                    window.open(currentStepData.action.href, '_blank')
                  } else if (currentStepData.action?.onClick) {
                    currentStepData.action.onClick()
                  }
                }}
              >
                {currentStepData.action.label}
              </Button>
            )}
            
            <Button onClick={handleNext} className="flex items-center gap-2">
              {currentStep === steps.length - 1 ? 'Complete Tour' : 'Next'}
              {currentStep < steps.length - 1 && <ArrowRight className="h-4 w-4" />}
              {currentStep === steps.length - 1 && <CheckCircle className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}