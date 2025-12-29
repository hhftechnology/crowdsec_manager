import React from 'react'
import { useFeatures, useContainers } from '@/contexts/DeploymentContext'
import { FeatureAvailability } from '@/lib/deployment-types'

export interface AdaptiveComponentProps {
  /** List of features that must be enabled */
  requiredFeatures?: (keyof FeatureAvailability)[]
  /** List of container names (substrings) that must be running */
  requiredContainers?: string[]
  /** Component to render if requirements are not met */
  fallbackComponent?: React.ComponentType
  /** Content to render if requirements are met */
  children: React.ReactNode
  /** If true, all listed features must be available. If false, at least one. Default: true */
  requireAllFeatures?: boolean
  /** If true, all listed containers must be running. If false, at least one. Default: true */
  requireAllContainers?: boolean
}

/**
 * A wrapper component that conditionally renders content based on the
 * current deployment context (enabled features and running containers).
 */
export function AdaptiveComponent({
  requiredFeatures = [],
  requiredContainers = [],
  fallbackComponent: Fallback,
  children,
  requireAllFeatures = true,
  requireAllContainers = true
}: AdaptiveComponentProps) {
  const features = useFeatures()
  const containers = useContainers()

  // check feature requirements
  const featuresMet = requiredFeatures.length === 0 || (
    requireAllFeatures
      ? requiredFeatures.every(f => features[f])
      : requiredFeatures.some(f => features[f])
  )

  // check container requirements
  const containersMet = requiredContainers.length === 0 || (
    requireAllContainers
      ? requiredContainers.every(reqName => 
          containers.some(c => c.name.toLowerCase().includes(reqName.toLowerCase()) && c.running)
        )
      : requiredContainers.some(reqName => 
          containers.some(c => c.name.toLowerCase().includes(reqName.toLowerCase()) && c.running)
        )
  )

  if (featuresMet && containersMet) {
    return <>{children}</>
  }

  if (Fallback) {
    return <Fallback />
  }

  return null
}
