import api from './api'
import { EnvironmentFlags } from '@/contexts/DeploymentContext'

export interface EnvironmentDetectionResult {
  flags: EnvironmentFlags
  detectedAt: Date
  success: boolean
  error?: string
}

export class EnvironmentDetector {
  private static instance: EnvironmentDetector
  private lastDetection: EnvironmentDetectionResult | null = null
  private cache: Map<string, boolean> = new Map()
  private cacheExpiry: Date | null = null
  private readonly CACHE_DURATION = 5 * 60 * 1000 // 5 minutes

  private constructor() {}

  static getInstance(): EnvironmentDetector {
    if (!EnvironmentDetector.instance) {
      EnvironmentDetector.instance = new EnvironmentDetector()
    }
    return EnvironmentDetector.instance
  }

  /**
   * Read environment flags from the backend
   */
  async readEnvironmentFlags(): Promise<EnvironmentFlags> {
    try {
      // Check cache first
      if (this.isCacheValid()) {
        return this.getCachedFlags()
      }

      // Try to get environment variables from validation API
      let envVars: Record<string, string> = {}
      try {
        const response = await api.validation.getEnvVars()
        if (response.data.success && response.data.data) {
          envVars = response.data.data
        }
      } catch (error) {
        console.warn('Failed to fetch environment variables, using defaults:', error)
      }

      // Parse environment flags
      const flags: EnvironmentFlags = {
        backupEnabled: this.parseBoolean(envVars.BACKUP_ENABLED, true),
        cronEnabled: this.parseBoolean(envVars.CRON_ENABLED, true),
        pangolinEnabled: this.parseBoolean(envVars.PANGOLIN_ENABLED, false),
        gerbilEnabled: this.parseBoolean(envVars.GERBIL_ENABLED, false),
        proxyType: envVars.PROXY_TYPE || envVars.COMPOSE_PROFILE || 'standalone',
        customFlags: this.parseCustomFlags(envVars)
      }

      // Update cache
      this.updateCache(flags)

      this.lastDetection = {
        flags,
        detectedAt: new Date(),
        success: true
      }

      return flags
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      
      this.lastDetection = {
        flags: this.getDefaultFlags(),
        detectedAt: new Date(),
        success: false,
        error: errorMessage
      }

      throw new Error(`Environment detection failed: ${errorMessage}`)
    }
  }

  /**
   * Check if a specific feature is enabled
   */
  async isFeatureEnabled(featureName: string): Promise<boolean> {
    try {
      const flags = await this.readEnvironmentFlags()
      
      switch (featureName.toLowerCase()) {
        case 'backup':
          return flags.backupEnabled
        case 'cron':
        case 'cronjobs':
          return flags.cronEnabled
        case 'pangolin':
          return flags.pangolinEnabled
        case 'gerbil':
          return flags.gerbilEnabled
        default:
          return flags.customFlags[featureName] || false
      }
    } catch (error) {
      console.error(`Failed to check if feature ${featureName} is enabled:`, error)
      return false
    }
  }

  /**
   * Get proxy configuration from environment
   */
  async getProxyConfiguration(): Promise<{ type: string; containerName?: string }> {
    try {
      const flags = await this.readEnvironmentFlags()
      
      return {
        type: flags.proxyType,
        containerName: this.getProxyContainerName(flags.proxyType)
      }
    } catch (error) {
      console.error('Failed to get proxy configuration:', error)
      return { type: 'standalone' }
    }
  }

  /**
   * Get the last detection result
   */
  getLastDetection(): EnvironmentDetectionResult | null {
    return this.lastDetection
  }

  /**
   * Clear the cache to force fresh detection
   */
  clearCache(): void {
    this.cache.clear()
    this.cacheExpiry = null
  }

  /**
   * Parse boolean value from string with default fallback
   */
  private parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
    if (!value) return defaultValue
    
    const lowerValue = value.toLowerCase()
    if (lowerValue === 'true' || lowerValue === '1' || lowerValue === 'yes' || lowerValue === 'on') {
      return true
    }
    if (lowerValue === 'false' || lowerValue === '0' || lowerValue === 'no' || lowerValue === 'off') {
      return false
    }
    
    return defaultValue
  }

  /**
   * Parse custom flags from environment variables
   */
  private parseCustomFlags(envVars: Record<string, string>): Record<string, boolean> {
    const customFlags: Record<string, boolean> = {}
    
    // Look for custom feature flags (e.g., FEATURE_X_ENABLED)
    Object.entries(envVars).forEach(([key, value]) => {
      if (key.startsWith('FEATURE_') && key.endsWith('_ENABLED')) {
        const featureName = key
          .replace('FEATURE_', '')
          .replace('_ENABLED', '')
          .toLowerCase()
        customFlags[featureName] = this.parseBoolean(value, false)
      }
    })
    
    return customFlags
  }

  /**
   * Get default environment flags
   */
  private getDefaultFlags(): EnvironmentFlags {
    return {
      backupEnabled: true,
      cronEnabled: true,
      pangolinEnabled: false,
      gerbilEnabled: false,
      proxyType: 'standalone',
      customFlags: {}
    }
  }

  /**
   * Check if cache is still valid
   */
  private isCacheValid(): boolean {
    return this.cacheExpiry !== null && new Date() < this.cacheExpiry && this.cache.size > 0
  }

  /**
   * Get cached flags
   */
  private getCachedFlags(): EnvironmentFlags {
    return {
      backupEnabled: this.cache.get('backupEnabled') || false,
      cronEnabled: this.cache.get('cronEnabled') || false,
      pangolinEnabled: this.cache.get('pangolinEnabled') || false,
      gerbilEnabled: this.cache.get('gerbilEnabled') || false,
      proxyType: this.cache.get('proxyType') as string || 'standalone',
      customFlags: JSON.parse(this.cache.get('customFlags') as string || '{}')
    }
  }

  /**
   * Update cache with new flags
   */
  private updateCache(flags: EnvironmentFlags): void {
    this.cache.set('backupEnabled', flags.backupEnabled)
    this.cache.set('cronEnabled', flags.cronEnabled)
    this.cache.set('pangolinEnabled', flags.pangolinEnabled)
    this.cache.set('gerbilEnabled', flags.gerbilEnabled)
    this.cache.set('proxyType', flags.proxyType)
    this.cache.set('customFlags', JSON.stringify(flags.customFlags))
    
    this.cacheExpiry = new Date(Date.now() + this.CACHE_DURATION)
  }

  /**
   * Get expected container name for proxy type
   */
  private getProxyContainerName(proxyType: string): string {
    switch (proxyType.toLowerCase()) {
      case 'traefik':
        return 'traefik'
      case 'nginx':
        return 'nginx'
      case 'caddy':
        return 'caddy'
      case 'haproxy':
        return 'haproxy'
      case 'zoraxy':
        return 'zoraxy'
      default:
        return 'proxy'
    }
  }
}

// Export singleton instance
export const environmentDetector = EnvironmentDetector.getInstance()

// Helper functions for external use
export async function readEnvironmentFlags(): Promise<EnvironmentFlags> {
  return environmentDetector.readEnvironmentFlags()
}

export async function isFeatureEnabled(featureName: string): Promise<boolean> {
  return environmentDetector.isFeatureEnabled(featureName)
}

export async function getProxyConfiguration(): Promise<{ type: string; containerName?: string }> {
  return environmentDetector.getProxyConfiguration()
}