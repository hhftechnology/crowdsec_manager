import { ContainerInfo, FeatureAvailability, EnvironmentFlags, ContainerRole } from '@/lib/deployment-types'

export interface FeatureDetectionResult {
  features: FeatureAvailability
  detectedAt: Date
  success: boolean
  error?: string
}

export interface DeploymentInfo {
  containers: ContainerInfo[]
  environment: EnvironmentFlags
  proxyType: string | null
}

export class FeatureDetector {
  private static instance: FeatureDetector
  private lastDetection: FeatureDetectionResult | null = null

  private constructor() {}

  static getInstance(): FeatureDetector {
    if (!FeatureDetector.instance) {
      FeatureDetector.instance = new FeatureDetector()
    }
    return FeatureDetector.instance
  }

  /**
   * Detect available features based on containers and environment
   */
  detectFeatures(containers: ContainerInfo[], environment: EnvironmentFlags): FeatureAvailability {
    try {
      const runningContainers = containers.filter(c => c.running)
      const proxyContainers = runningContainers.filter(c => c.role === ContainerRole.PROXY)
      const securityContainers = runningContainers.filter(c => c.role === ContainerRole.SECURITY)
      const addonContainers = runningContainers.filter(c => c.role === ContainerRole.ADDON)

      const features: FeatureAvailability = {
        // Captcha requires proxy container with captcha capability
        captcha: proxyContainers.some(c => c.capabilities.includes('captcha')),
        
        // Backup depends on environment flag
        backup: environment.backupEnabled,
        
        // Cron jobs depend on environment flag
        cronJobs: environment.cronEnabled,
        
        // Proxy whitelist requires proxy container with whitelist capability
        whitelistProxy: proxyContainers.some(c => c.capabilities.includes('whitelist')),
        
        // Logs available if any container supports logs
        logs: runningContainers.some(c => c.capabilities.includes('logs')),
        
        // Pangolin availability
        pangolin: environment.pangolinEnabled && 
                 addonContainers.some(c => c.name.toLowerCase().includes('pangolin')),
        
        // Gerbil availability
        gerbil: environment.gerbilEnabled && 
               addonContainers.some(c => c.name.toLowerCase().includes('gerbil')),
        
        // AppSec requires container with appsec capability
        appsec: runningContainers.some(c => c.capabilities.includes('appsec')),
        
        // Bouncer requires container with bouncer capability
        bouncer: runningContainers.some(c => c.capabilities.includes('bouncer'))
      }

      this.lastDetection = {
        features,
        detectedAt: new Date(),
        success: true
      }

      return features
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      
      const defaultFeatures: FeatureAvailability = {
        captcha: false,
        backup: false,
        cronJobs: false,
        whitelistProxy: false,
        logs: false,
        pangolin: false,
        gerbil: false,
        appsec: false,
        bouncer: false
      }

      this.lastDetection = {
        features: defaultFeatures,
        detectedAt: new Date(),
        success: false,
        error: errorMessage
      }

      return defaultFeatures
    }
  }

  /**
   * Get capabilities for a specific proxy type
   */
  getProxyCapabilities(proxyType: string): string[] {
    switch (proxyType.toLowerCase()) {
      case 'traefik':
        return ['whitelist', 'captcha', 'logs', 'bouncer', 'appsec', 'health']
      case 'nginx':
        return ['whitelist', 'logs', 'bouncer', 'health']
      case 'caddy':
        return ['whitelist', 'logs', 'bouncer', 'health']
      case 'haproxy':
        return ['whitelist', 'logs', 'bouncer', 'health']
      case 'zoraxy':
        return ['whitelist', 'logs', 'health']
      case 'standalone':
        return ['health']
      default:
        return ['health']
    }
  }

  /**
   * Check if a specific feature is supported by the deployment
   */
  isFeatureSupported(feature: string, deployment: DeploymentInfo): boolean {
    const features = this.detectFeatures(deployment.containers, deployment.environment)
    
    switch (feature.toLowerCase()) {
      case 'captcha':
        return features.captcha
      case 'backup':
        return features.backup
      case 'cron':
      case 'cronjobs':
        return features.cronJobs
      case 'whitelist':
      case 'whitelistproxy':
        return features.whitelistProxy
      case 'logs':
        return features.logs
      case 'pangolin':
        return features.pangolin
      case 'gerbil':
        return features.gerbil
      case 'appsec':
        return features.appsec
      case 'bouncer':
        return features.bouncer
      default:
        return false
    }
  }

  /**
   * Get detailed feature analysis
   */
  analyzeFeatureAvailability(deployment: DeploymentInfo): FeatureAnalysis {
    const features = this.detectFeatures(deployment.containers, deployment.environment)
    const runningContainers = deployment.containers.filter(c => c.running)
    
    return {
      features,
      analysis: {
        totalContainers: deployment.containers.length,
        runningContainers: runningContainers.length,
        proxyContainers: runningContainers.filter(c => c.role === ContainerRole.PROXY).length,
        securityContainers: runningContainers.filter(c => c.role === ContainerRole.SECURITY).length,
        addonContainers: runningContainers.filter(c => c.role === ContainerRole.ADDON).length,
        availableFeatures: Object.values(features).filter(Boolean).length,
        totalFeatures: Object.keys(features).length
      },
      recommendations: this.generateRecommendations(deployment, features)
    }
  }

  /**
   * Get feature availability calculator based on container presence
   */
  calculateFeatureAvailability(containers: ContainerInfo[], environment: EnvironmentFlags): FeatureAvailability {
    return this.detectFeatures(containers, environment)
  }

  /**
   * Get features that require specific containers
   */
  getContainerDependentFeatures(): Record<string, string[]> {
    return {
      captcha: ['traefik'], // Only Traefik supports captcha currently
      whitelistProxy: ['traefik', 'nginx', 'caddy', 'haproxy'], // Any proxy can do whitelist
      appsec: ['traefik'], // Only Traefik supports AppSec
      bouncer: ['traefik', 'nginx', 'caddy', 'haproxy', 'crowdsec'], // Most containers support bouncer
      logs: ['traefik', 'nginx', 'caddy', 'haproxy', 'crowdsec', 'pangolin', 'gerbil'] // Most containers have logs
    }
  }

  /**
   * Get features that depend on environment variables
   */
  getEnvironmentDependentFeatures(): Record<string, string[]> {
    return {
      backup: ['BACKUP_ENABLED'],
      cronJobs: ['CRON_ENABLED'],
      pangolin: ['PANGOLIN_ENABLED'],
      gerbil: ['GERBIL_ENABLED']
    }
  }

  /**
   * Check if a feature can be enabled with current deployment
   */
  canFeatureBeEnabled(feature: string, deployment: DeploymentInfo): { possible: boolean; reason: string } {
    const containerDeps = this.getContainerDependentFeatures()
    const envDeps = this.getEnvironmentDependentFeatures()
    
    const runningContainers = deployment.containers.filter(c => c.running)
    
    // Check container dependencies
    if (containerDeps[feature]) {
      const hasRequiredContainer = containerDeps[feature].some(requiredContainer =>
        runningContainers.some(c => c.name.toLowerCase().includes(requiredContainer))
      )
      
      if (!hasRequiredContainer) {
        return {
          possible: false,
          reason: `Requires one of these containers to be running: ${containerDeps[feature].join(', ')}`
        }
      }
    }
    
    // Check environment dependencies
    if (envDeps[feature]) {
      const missingEnvVars = envDeps[feature].filter(envVar => {
        switch (envVar) {
          case 'BACKUP_ENABLED':
            return !deployment.environment.backupEnabled
          case 'CRON_ENABLED':
            return !deployment.environment.cronEnabled
          case 'PANGOLIN_ENABLED':
            return !deployment.environment.pangolinEnabled
          case 'GERBIL_ENABLED':
            return !deployment.environment.gerbilEnabled
          default:
            return false
        }
      })
      
      if (missingEnvVars.length > 0) {
        return {
          possible: false,
          reason: `Requires these environment variables to be enabled: ${missingEnvVars.join(', ')}`
        }
      }
    }
    
    return { possible: true, reason: 'Feature can be enabled' }
  }
  /**
   * Get the last detection result
   */
  getLastDetection(): FeatureDetectionResult | null {
    return this.lastDetection
  }

  /**
   * Generate recommendations for improving feature availability
   */
  private generateRecommendations(deployment: DeploymentInfo, features: FeatureAvailability): string[] {
    const recommendations: string[] = []
    const runningContainers = deployment.containers.filter(c => c.running)
    const proxyContainers = runningContainers.filter(c => c.role === ContainerRole.PROXY)

    // Captcha recommendations
    if (!features.captcha && proxyContainers.length > 0) {
      const supportsCaptcha = proxyContainers.some(c => 
        c.name.toLowerCase().includes('traefik')
      )
      if (supportsCaptcha) {
        recommendations.push('Configure captcha settings to enable captcha protection')
      } else {
        recommendations.push('Consider using Traefik for captcha functionality')
      }
    }

    // Backup recommendations
    if (!features.backup) {
      recommendations.push('Enable backup functionality in environment variables')
    }

    // Proxy whitelist recommendations
    if (!features.whitelistProxy && proxyContainers.length === 0) {
      recommendations.push('Deploy a proxy container (Traefik, Nginx, etc.) for advanced whitelist features')
    }

    // AppSec recommendations
    if (!features.appsec && proxyContainers.some(c => c.name.toLowerCase().includes('traefik'))) {
      recommendations.push('Enable AppSec in Traefik configuration for advanced security features')
    }

    // Addon recommendations
    if (!features.pangolin && !deployment.environment.pangolinEnabled) {
      recommendations.push('Enable Pangolin in environment for enhanced monitoring capabilities')
    }

    if (!features.gerbil && !deployment.environment.gerbilEnabled) {
      recommendations.push('Enable Gerbil in environment for additional security features')
    }

    return recommendations
  }
}

export interface FeatureAnalysis {
  features: FeatureAvailability
  analysis: {
    totalContainers: number
    runningContainers: number
    proxyContainers: number
    securityContainers: number
    addonContainers: number
    availableFeatures: number
    totalFeatures: number
  }
  recommendations: string[]
}

// Export singleton instance
export const featureDetector = FeatureDetector.getInstance()

// Helper functions for external use
export function detectFeatures(containers: ContainerInfo[], environment: EnvironmentFlags): FeatureAvailability {
  return featureDetector.detectFeatures(containers, environment)
}

export function getProxyCapabilities(proxyType: string): string[] {
  return featureDetector.getProxyCapabilities(proxyType)
}

export function isFeatureSupported(feature: string, deployment: DeploymentInfo): boolean {
  return featureDetector.isFeatureSupported(feature, deployment)
}

export function analyzeFeatureAvailability(deployment: DeploymentInfo): FeatureAnalysis {
  return featureDetector.analyzeFeatureAvailability(deployment)
}

export function calculateFeatureAvailability(containers: ContainerInfo[], environment: EnvironmentFlags): FeatureAvailability {
  return featureDetector.calculateFeatureAvailability(containers, environment)
}

export function canFeatureBeEnabled(feature: string, deployment: DeploymentInfo): { possible: boolean; reason: string } {
  return featureDetector.canFeatureBeEnabled(feature, deployment)
}

export function getContainerDependentFeatures(): Record<string, string[]> {
  return featureDetector.getContainerDependentFeatures()
}

export function getEnvironmentDependentFeatures(): Record<string, string[]> {
  return featureDetector.getEnvironmentDependentFeatures()
}