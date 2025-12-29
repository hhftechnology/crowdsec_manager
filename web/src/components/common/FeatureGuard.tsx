import { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useFeature } from '@/contexts/DeploymentContext'
import { FeatureAvailability } from '@/lib/deployment-types'
import { Button } from '@/components/ui/button'
import { AlertTriangle } from 'lucide-react'

interface FeatureGuardProps {
  feature: keyof FeatureAvailability
  children: ReactNode
  /** If true, redirects to dashboard instead of showing error message */
  redirect?: boolean
  /** Custom fallback component */
  fallback?: ReactNode
}

export function FeatureGuard({ 
  feature, 
  children, 
  redirect = false,
  fallback 
}: FeatureGuardProps) {
  const isEnabled = useFeature(feature)

  if (isEnabled) {
    return <>{children}</>
  }

  if (redirect) {
    return <Navigate to="/" replace />
  }

  if (fallback) {
    return <>{fallback}</>
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] text-center p-8">
      <div className="bg-destructive/10 p-4 rounded-full mb-4">
        <AlertTriangle className="h-10 w-10 text-destructive" />
      </div>
      <h2 className="text-2xl font-bold tracking-tight mb-2">Feature Unavailable</h2>
      <p className="text-muted-foreground max-w-md mb-6">
        The feature <span className="font-mono font-medium text-foreground">{feature}</span> is not currently available in your deployment configuration.
      </p>
      <Button asChild variant="outline">
        <a href="/">Return to Dashboard</a>
      </Button>
    </div>
  )
}
