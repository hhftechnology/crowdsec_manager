import api from './api'
import { ContainerInfo, ContainerStatus, ContainerRole, HealthStatus } from '@/lib/deployment-types'

export interface ContainerDetectionResult {
  containers: ContainerInfo[]
  detectedAt: Date
  success: boolean
  error?: string
}

export class ContainerDetector {
  private static instance: ContainerDetector
  private listeners: Array<(containers: ContainerInfo[]) => void> = []
  private lastDetection: ContainerDetectionResult | null = null
  private monitoringInterval: NodeJS.Timeout | null = null

  private constructor() {}

  static getInstance(): ContainerDetector {
    if (!ContainerDetector.instance) {
      ContainerDetector.instance = new ContainerDetector()
    }
    return ContainerDetector.instance
  }

  /**
   * Detect all containers in the current deployment
   */
  async detectContainers(): Promise<ContainerInfo[]> {
    try {
      const response = await api.health.checkStack()
      
      if (!response.data.success || !response.data.data?.containers) {
        throw new Error('Failed to retrieve container information')
      }

      const containers: ContainerInfo[] = response.data.data.containers.map(container => ({
        name: container.name,
        id: container.id || '',
        status: this.mapContainerStatus(container.status),
        running: container.running,
        capabilities: this.determineContainerCapabilities(container.name, container.running),
        role: this.determineContainerRole(container.name),
        healthStatus: container.running ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY
      }))

      this.lastDetection = {
        containers,
        detectedAt: new Date(),
        success: true
      }

      // Notify listeners of container changes
      this.notifyListeners(containers)

      return containers
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      
      this.lastDetection = {
        containers: [],
        detectedAt: new Date(),
        success: false,
        error: errorMessage
      }

      throw new Error(`Container detection failed: ${errorMessage}`)
    }
  }

  /**
   * Monitor container changes and notify listeners
   */
  monitorContainerChanges(callback: (containers: ContainerInfo[]) => void): void {
    this.listeners.push(callback)

    // Start monitoring if not already started
    if (!this.monitoringInterval) {
      this.startMonitoring()
    }

    // Immediately call with current data if available
    if (this.lastDetection?.success) {
      callback(this.lastDetection.containers)
    }
  }

  /**
   * Stop monitoring container changes for a specific callback
   */
  stopMonitoring(callback: (containers: ContainerInfo[]) => void): void {
    const index = this.listeners.indexOf(callback)
    if (index > -1) {
      this.listeners.splice(index, 1)
    }

    // Stop monitoring if no listeners remain
    if (this.listeners.length === 0 && this.monitoringInterval) {
      clearInterval(this.monitoringInterval)
      this.monitoringInterval = null
    }
  }

  /**
   * Get capabilities for a specific container
   */
  async getContainerCapabilities(containerName: string): Promise<string[]> {
    try {
      const containers = await this.detectContainers()
      const container = containers.find(c => c.name === containerName)
      return container?.capabilities || []
    } catch (error) {
      console.error(`Failed to get capabilities for container ${containerName}:`, error)
      return []
    }
  }

  /**
   * Check if a specific container is running
   */
  async isContainerRunning(containerName: string): Promise<boolean> {
    try {
      const containers = await this.detectContainers()
      const container = containers.find(c => c.name === containerName)
      return container?.running || false
    } catch (error) {
      console.error(`Failed to check if container ${containerName} is running:`, error)
      return false
    }
  }

  /**
   * Get detailed health status for all containers
   */
  async getContainerHealthStatus(): Promise<Record<string, HealthStatus>> {
    try {
      const containers = await this.detectContainers()
      const healthStatus: Record<string, HealthStatus> = {}

      for (const container of containers) {
        if (container.running) {
          // For running containers, determine health based on capabilities and role
          if (container.capabilities.length > 0) {
            healthStatus[container.name] = HealthStatus.HEALTHY
          } else {
            healthStatus[container.name] = HealthStatus.DEGRADED
          }
        } else {
          healthStatus[container.name] = HealthStatus.UNHEALTHY
        }
      }

      return healthStatus
    } catch (error) {
      console.error('Failed to get container health status:', error)
      return {}
    }
  }

  /**
   * Get containers grouped by role
   */
  async getContainersByRole(): Promise<Record<ContainerRole, ContainerInfo[]>> {
    try {
      const containers = await this.detectContainers()
      const grouped: Record<ContainerRole, ContainerInfo[]> = {
        [ContainerRole.PROXY]: [],
        [ContainerRole.SECURITY]: [],
        [ContainerRole.ADDON]: [],
        [ContainerRole.MONITORING]: []
      }

      containers.forEach(container => {
        grouped[container.role].push(container)
      })

      return grouped
    } catch (error) {
      console.error('Failed to group containers by role:', error)
      return {
        [ContainerRole.PROXY]: [],
        [ContainerRole.SECURITY]: [],
        [ContainerRole.ADDON]: [],
        [ContainerRole.MONITORING]: []
      }
    }
  }

  /**
   * Get running containers only
   */
  async getRunningContainers(): Promise<ContainerInfo[]> {
    try {
      const containers = await this.detectContainers()
      return containers.filter(c => c.running)
    } catch (error) {
      console.error('Failed to get running containers:', error)
      return []
    }
  }

  /**
   * Start periodic monitoring of container changes
   */
  private startMonitoring(): void {
    // Clear any existing interval
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval)
    }

    this.monitoringInterval = setInterval(async () => {
      try {
        const previousContainers = this.lastDetection?.containers || []
        const currentContainers = await this.detectContainers()
        
        // Check if containers have changed
        const hasChanged = this.hasContainerStateChanged(previousContainers, currentContainers)
        
        if (hasChanged) {
          console.log('Container state changed, notifying listeners')
        }
      } catch (error) {
        console.error('Container monitoring error:', error)
        
        // Notify listeners of monitoring error
        this.notifyListeners([])
      }
    }, 15000) // Check every 15 seconds
  }

  /**
   * Get the last detection result
   */
  getLastDetection(): ContainerDetectionResult | null {
    return this.lastDetection
  }

  /**
   * Check if container state has changed significantly
   */
  private hasContainerStateChanged(previous: ContainerInfo[], current: ContainerInfo[]): boolean {
    if (previous.length !== current.length) {
      return true
    }

    // Check for status changes in existing containers
    for (let i = 0; i < previous.length; i++) {
      const prev = previous[i]
      const curr = current[i]
      
      if (prev.name !== curr.name || 
          prev.running !== curr.running || 
          prev.status !== curr.status ||
          prev.capabilities.length !== curr.capabilities.length) {
        return true
      }
    }

    return false
  }

  /**
   * Notify all listeners of container changes
   */
  private notifyListeners(containers: ContainerInfo[]): void {
    this.listeners.forEach(callback => {
      try {
        callback(containers)
      } catch (error) {
        console.error('Error in container change listener:', error)
      }
    })
  }

  /**
   * Map container status string to enum
   */
  private mapContainerStatus(status: string): ContainerStatus {
    switch (status.toLowerCase()) {
      case 'running':
        return ContainerStatus.RUNNING
      case 'stopped':
      case 'exited':
        return ContainerStatus.STOPPED
      case 'restarting':
        return ContainerStatus.RESTARTING
      default:
        return ContainerStatus.UNKNOWN
    }
  }

  /**
   * Determine container role based on name
   */
  private determineContainerRole(containerName: string): ContainerRole {
    const name = containerName.toLowerCase()
    
    if (name.includes('traefik') || name.includes('nginx') || name.includes('caddy') || 
        name.includes('haproxy') || name.includes('zoraxy')) {
      return ContainerRole.PROXY
    }
    
    if (name.includes('crowdsec')) {
      return ContainerRole.SECURITY
    }
    
    if (name.includes('pangolin') || name.includes('gerbil')) {
      return ContainerRole.ADDON
    }
    
    return ContainerRole.MONITORING
  }

  /**
   * Determine container capabilities based on name and running status
   */
  private determineContainerCapabilities(containerName: string, running: boolean): string[] {
    if (!running) return []
    
    const name = containerName.toLowerCase()
    const capabilities: string[] = ['health'] // All running containers have health capability
    
    if (name.includes('traefik')) {
      capabilities.push('whitelist', 'captcha', 'logs', 'bouncer', 'appsec')
    } else if (name.includes('nginx')) {
      capabilities.push('whitelist', 'logs', 'bouncer')
    } else if (name.includes('caddy')) {
      capabilities.push('whitelist', 'logs', 'bouncer')
    } else if (name.includes('haproxy')) {
      capabilities.push('whitelist', 'logs', 'bouncer')
    } else if (name.includes('crowdsec')) {
      capabilities.push('bouncer', 'logs')
    } else if (name.includes('pangolin') || name.includes('gerbil')) {
      capabilities.push('logs')
    }
    
    return capabilities
  }
}

// Export singleton instance
export const containerDetector = ContainerDetector.getInstance()

// Helper functions for external use
export async function detectContainers(): Promise<ContainerInfo[]> {
  return containerDetector.detectContainers()
}

export function monitorContainerChanges(callback: (containers: ContainerInfo[]) => void): () => void {
  containerDetector.monitorContainerChanges(callback)
  
  // Return cleanup function
  return () => containerDetector.stopMonitoring(callback)
}

export async function getContainerCapabilities(containerName: string): Promise<string[]> {
  return containerDetector.getContainerCapabilities(containerName)
}

export async function isContainerRunning(containerName: string): Promise<boolean> {
  return containerDetector.isContainerRunning(containerName)
}

export async function getContainerHealthStatus(): Promise<Record<string, HealthStatus>> {
  return containerDetector.getContainerHealthStatus()
}

export async function getContainersByRole(): Promise<Record<ContainerRole, ContainerInfo[]>> {
  return containerDetector.getContainersByRole()
}

export async function getRunningContainers(): Promise<ContainerInfo[]> {
  return containerDetector.getRunningContainers()
}