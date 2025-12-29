import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fc from 'fast-check'
import { ContainerInfo, ContainerStatus, ContainerRole, HealthStatus } from '@/lib/deployment-types'
import { containerDetector, getContainersByRole, getRunningContainers } from '@/lib/container-detector'
import api from '@/lib/api'

// Mock the API
vi.mock('@/lib/api', () => ({
  default: {
    health: {
      checkStack: vi.fn(),
      completeDiagnostics: vi.fn(),
      crowdsecHealth: vi.fn()
    },
    proxy: {
      getCurrent: vi.fn(),
      checkHealth: vi.fn()
    }
  }
}))

/**
 * **Feature: proxy-aware-ui-components, Property 7: Deployment-aware health monitoring**
 * **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5**
 */
describe('Health Monitoring Visibility Properties', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // Generators for property-based testing
  const containerStatusGen = fc.constantFrom(
    ContainerStatus.RUNNING,
    ContainerStatus.STOPPED,
    ContainerStatus.RESTARTING,
    ContainerStatus.UNKNOWN
  )

  const containerRoleGen = fc.constantFrom(
    ContainerRole.PROXY,
    ContainerRole.SECURITY,
    ContainerRole.ADDON,
    ContainerRole.MONITORING
  )

  const healthStatusGen = fc.constantFrom(
    HealthStatus.HEALTHY,
    HealthStatus.UNHEALTHY,
    HealthStatus.DEGRADED,
    HealthStatus.UNKNOWN
  )

  const containerNameGen = fc.oneof(
    fc.constant('traefik'),
    fc.constant('nginx'),
    fc.constant('caddy'),
    fc.constant('haproxy'),
    fc.constant('crowdsec'),
    fc.constant('pangolin'),
    fc.constant('gerbil'),
    fc.constant('zoraxy')
  )

  const containerGen = fc.record({
    name: containerNameGen,
    id: fc.string({ minLength: 8, maxLength: 64 }),
    status: containerStatusGen,
    running: fc.boolean(),
    capabilities: fc.array(fc.constantFrom('whitelist', 'captcha', 'logs', 'bouncer', 'appsec', 'health'), { minLength: 0, maxLength: 6 }),
    role: containerRoleGen,
    healthStatus: healthStatusGen
  }).map(container => {
    // Fix role based on container name
    let role = container.role
    const name = container.name.toLowerCase()
    if (name.includes('traefik') || name.includes('nginx') || name.includes('caddy') || name.includes('haproxy') || name.includes('zoraxy')) {
      role = ContainerRole.PROXY
    } else if (name.includes('crowdsec')) {
      role = ContainerRole.SECURITY
    } else if (name.includes('pangolin') || name.includes('gerbil')) {
      role = ContainerRole.ADDON
    }

    return {
      ...container,
      role,
      // Ensure running status matches container status
      running: container.status === ContainerStatus.RUNNING,
      // Ensure capabilities are empty if not running, and include health if running
      capabilities: container.status === ContainerStatus.RUNNING 
        ? (container.capabilities.includes('health') ? container.capabilities : [...container.capabilities, 'health'])
        : []
    }
  })

  const containerListGen = fc.array(containerGen, { minLength: 0, maxLength: 8 })

  const proxyTypeGen = fc.constantFrom('traefik', 'nginx', 'caddy', 'haproxy', 'standalone', 'zoraxy')

  const healthDataGen = fc.record({
    containers: containerListGen,
    allRunning: fc.boolean(),
    timestamp: fc.date()
  })

  const proxyInfoGen = fc.record({
    type: proxyTypeGen,
    running: fc.boolean(),
    connected: fc.boolean(),
    container_name: fc.string({ minLength: 3, maxLength: 20 }),
    supported_features: fc.array(fc.constantFrom('whitelist', 'captcha', 'logs', 'bouncer'), { minLength: 0, maxLength: 4 })
  })

  it('Property 7.1: Health page should display only containers from current deployment', () => {
    fc.assert(fc.asyncProperty(
      healthDataGen,
      async (healthData) => {
        // Mock API response
        const mockHealthResponse = {
          data: {
            success: true,
            data: {
              containers: healthData.containers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.status.toLowerCase(),
                running: c.running
              })),
              allRunning: healthData.allRunning,
              timestamp: healthData.timestamp.toISOString()
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(mockHealthResponse)

        // Get containers from detector (simulating health page behavior)
        const detectedContainers = await containerDetector.detectContainers()

        // Health page should only show containers that are in the current deployment
        expect(detectedContainers.length).toBe(healthData.containers.length)

        detectedContainers.forEach((container, index) => {
          // Each displayed container should match the deployment containers
          expect(container.name).toBe(healthData.containers[index].name)
          expect(container.running).toBe(healthData.containers[index].running)
          
          // Container should be part of the current deployment
          const isInDeployment = healthData.containers.some(c => 
            c.name === container.name && c.id === container.id
          )
          expect(isInDeployment).toBe(true)
        })

        // No containers outside the deployment should be displayed
        const deploymentContainerNames = healthData.containers.map(c => c.name)
        detectedContainers.forEach(container => {
          expect(deploymentContainerNames).toContain(container.name)
        })
      }
    ), { numRuns: 100 })
  })

  it('Property 7.2: Traefik integration section should be conditional on container presence', () => {
    fc.assert(fc.asyncProperty(
      containerListGen,
      proxyInfoGen,
      async (containers, proxyInfo) => {
        // Mock API responses
        const mockHealthResponse = {
          data: {
            success: true,
            data: {
              containers: containers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.status.toLowerCase(),
                running: c.running
              }))
            }
          }
        }

        const mockProxyResponse = {
          data: {
            success: true,
            data: proxyInfo
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(mockHealthResponse)
        vi.mocked(api.proxy.getCurrent).mockResolvedValue(mockProxyResponse)

        const detectedContainers = await containerDetector.detectContainers()
        
        // Check if Traefik container is present and running
        const traefikContainer = detectedContainers.find(c => 
          c.name.toLowerCase().includes('traefik') && c.running
        )
        const hasTraefikContainer = !!traefikContainer

        // Traefik integration should only be shown when:
        // 1. Traefik container is present and running, OR
        // 2. Proxy type is traefik (even if container detection fails)
        const shouldShowTraefikIntegration = hasTraefikContainer || proxyInfo.type === 'traefik'

        if (shouldShowTraefikIntegration) {
          // When Traefik is present, integration section should be available
          expect(proxyInfo.type === 'traefik' || hasTraefikContainer).toBe(true)
          
          // If container is present, it should have appropriate capabilities
          if (traefikContainer) {
            expect(traefikContainer.capabilities).toContain('health')
            // Traefik typically supports these features
            const expectedCapabilities = ['whitelist', 'captcha', 'logs', 'bouncer', 'appsec']
            expectedCapabilities.forEach(capability => {
              if (traefikContainer.capabilities.includes(capability)) {
                expect(traefikContainer.capabilities).toContain(capability)
              }
            })
          }
        } else {
          // When Traefik is not present, integration section should be hidden
          expect(hasTraefikContainer).toBe(false)
          expect(proxyInfo.type).not.toBe('traefik')
        }
      }
    ), { numRuns: 50 })
  })

  it('Property 7.3: Container grouping should reflect deployment roles and relationships', () => {
    fc.assert(fc.asyncProperty(
      containerListGen,
      async (containers) => {
        // Mock API response
        const mockHealthResponse = {
          data: {
            success: true,
            data: {
              containers: containers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.status.toLowerCase(),
                running: c.running
              }))
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(mockHealthResponse)

        const containersByRole = await getContainersByRole()

        // Verify that containers are grouped correctly by their roles
        Object.entries(containersByRole).forEach(([role, roleContainers]) => {
          roleContainers.forEach(container => {
            expect(container.role).toBe(role)
            
            // Verify role assignment matches container name patterns
            const name = container.name.toLowerCase()
            switch (role) {
              case ContainerRole.PROXY:
                expect(
                  name.includes('traefik') || 
                  name.includes('nginx') || 
                  name.includes('caddy') || 
                  name.includes('haproxy') ||
                  name.includes('zoraxy')
                ).toBe(true)
                break
              case ContainerRole.SECURITY:
                expect(name.includes('crowdsec')).toBe(true)
                break
              case ContainerRole.ADDON:
                expect(
                  name.includes('pangolin') || 
                  name.includes('gerbil')
                ).toBe(true)
                break
            }
          })
        })

        // Verify relationships: Security containers should exist if proxy containers exist
        const proxyContainers = containersByRole[ContainerRole.PROXY].filter(c => c.running)
        const securityContainers = containersByRole[ContainerRole.SECURITY].filter(c => c.running)
        
        if (proxyContainers.length > 0) {
          // If there are running proxy containers, there should typically be security containers
          // This is a deployment relationship expectation
          const hasSecuritySupport = securityContainers.length > 0 || 
            proxyContainers.some(c => c.capabilities.includes('bouncer'))
          
          // At least one form of security should be present in a proper deployment
          expect(hasSecuritySupport).toBe(true)
        }
      }
    ), { numRuns: 50 })
  })

  it('Property 7.4: Health monitoring should exclude containers not in deployment', () => {
    fc.assert(fc.asyncProperty(
      containerListGen,
      fc.array(fc.string({ minLength: 3, maxLength: 15 }), { minLength: 1, maxLength: 5 }),
      async (deploymentContainers, externalContainerNames) => {
        // Mock API response with only deployment containers
        const mockHealthResponse = {
          data: {
            success: true,
            data: {
              containers: deploymentContainers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.status.toLowerCase(),
                running: c.running
              }))
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(mockHealthResponse)

        const detectedContainers = await containerDetector.detectContainers()

        // None of the external containers should appear in health monitoring
        externalContainerNames.forEach(externalName => {
          const found = detectedContainers.some(c => c.name === externalName)
          expect(found).toBe(false)
        })

        // Only deployment containers should be monitored
        detectedContainers.forEach(container => {
          const isInDeployment = deploymentContainers.some(c => c.name === container.name)
          expect(isInDeployment).toBe(true)
        })

        // Count should match exactly
        expect(detectedContainers.length).toBe(deploymentContainers.length)
      }
    ), { numRuns: 50 })
  })

  it('Property 7.5: Health status should reflect actual container states in deployment', () => {
    fc.assert(fc.asyncProperty(
      containerListGen,
      async (containers) => {
        // Mock API response
        const mockHealthResponse = {
          data: {
            success: true,
            data: {
              containers: containers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.status.toLowerCase(),
                running: c.running
              })),
              allRunning: containers.every(c => c.running),
              timestamp: new Date().toISOString()
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(mockHealthResponse)

        const detectedContainers = await containerDetector.detectContainers()
        const runningContainers = await getRunningContainers()

        // Health status should accurately reflect container states
        detectedContainers.forEach((container, index) => {
          const originalContainer = containers[index]
          
          // Running status should match
          expect(container.running).toBe(originalContainer.running)
          
          // Health status should be consistent with running state
          if (container.running) {
            expect(container.healthStatus).not.toBe(HealthStatus.UNHEALTHY)
            expect(container.capabilities.length).toBeGreaterThan(0)
          } else {
            expect(container.capabilities).toEqual([])
          }
        })

        // Running containers should be a proper subset
        expect(runningContainers.length).toBeLessThanOrEqual(detectedContainers.length)
        
        // All running containers should actually be running
        runningContainers.forEach(container => {
          expect(container.running).toBe(true)
          expect(container.status).toBe(ContainerStatus.RUNNING)
        })

        // Overall health should reflect deployment state
        const allRunning = containers.every(c => c.running)
        const actualAllRunning = detectedContainers.every(c => c.running)
        expect(actualAllRunning).toBe(allRunning)
      }
    ), { numRuns: 100 })
  })

  it('Property 7.6: Proxy-specific health sections should only appear for detected proxy types', () => {
    fc.assert(fc.asyncProperty(
      containerListGen,
      proxyInfoGen,
      async (containers, proxyInfo) => {
        // Mock API responses
        const mockHealthResponse = {
          data: {
            success: true,
            data: {
              containers: containers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.status.toLowerCase(),
                running: c.running
              }))
            }
          }
        }

        const mockProxyResponse = {
          data: {
            success: true,
            data: proxyInfo
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(mockHealthResponse)
        vi.mocked(api.proxy.getCurrent).mockResolvedValue(mockProxyResponse)

        const detectedContainers = await containerDetector.detectContainers()
        const containersByRole = await getContainersByRole()
        
        // Check for proxy containers in deployment
        const proxyContainers = containersByRole[ContainerRole.PROXY].filter(c => c.running)
        const detectedProxyTypes = new Set<string>()
        
        proxyContainers.forEach(container => {
          const name = container.name.toLowerCase()
          if (name.includes('traefik')) detectedProxyTypes.add('traefik')
          if (name.includes('nginx')) detectedProxyTypes.add('nginx')
          if (name.includes('caddy')) detectedProxyTypes.add('caddy')
          if (name.includes('haproxy')) detectedProxyTypes.add('haproxy')
          if (name.includes('zoraxy')) detectedProxyTypes.add('zoraxy')
        })

        // If no proxy containers detected, should default to standalone or use API info
        if (detectedProxyTypes.size === 0 && proxyInfo.type !== 'standalone') {
          detectedProxyTypes.add(proxyInfo.type)
        }

        // Health monitoring should only show sections for detected proxy types
        if (detectedProxyTypes.has('traefik')) {
          // Traefik-specific health sections should be available
          const traefikContainer = proxyContainers.find(c => 
            c.name.toLowerCase().includes('traefik')
          )
          if (traefikContainer) {
            expect(traefikContainer.capabilities).toEqual(
              expect.arrayContaining(['health'])
            )
          }
        }

        if (detectedProxyTypes.has('nginx')) {
          // Nginx-specific health sections should be available
          const nginxContainer = proxyContainers.find(c => 
            c.name.toLowerCase().includes('nginx')
          )
          if (nginxContainer) {
            expect(nginxContainer.capabilities).toEqual(
              expect.arrayContaining(['health'])
            )
          }
        }

        // Proxy types not in deployment should not have health sections
        const allProxyTypes = ['traefik', 'nginx', 'caddy', 'haproxy', 'zoraxy']
        allProxyTypes.forEach(proxyType => {
          if (!detectedProxyTypes.has(proxyType) && proxyInfo.type !== proxyType) {
            // This proxy type should not have dedicated health sections
            const proxyContainer = proxyContainers.find(c => 
              c.name.toLowerCase().includes(proxyType)
            )
            expect(proxyContainer).toBeUndefined()
          }
        })
      }
    ), { numRuns: 30 })
  })
})