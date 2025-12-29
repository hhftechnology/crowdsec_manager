import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fc from 'fast-check'
import { DeploymentProvider, useDeployment, ContainerInfo, ContainerStatus, ContainerRole, HealthStatus } from '@/contexts/DeploymentContext'
import { containerDetector } from '@/lib/container-detector'
import { environmentDetector } from '@/lib/environment-detector'
import { featureDetector } from '@/lib/feature-detector'
import api from '@/lib/api'

// Mock the API
vi.mock('@/lib/api', () => ({
  default: {
    health: {
      checkStack: vi.fn()
    },
    proxy: {
      getCurrent: vi.fn()
    },
    validation: {
      getEnvVars: vi.fn()
    }
  }
}))

/**
 * **Feature: proxy-aware-ui-components, Property 10: Dynamic deployment detection**
 * **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5**
 */
describe('Dynamic Deployment Detection Properties', () => {
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
    capabilities: fc.array(fc.constantFrom('whitelist', 'captcha', 'logs', 'bouncer', 'appsec', 'health'), { minLength: 1, maxLength: 6 }),
    role: containerRoleGen,
    healthStatus: healthStatusGen
  }).map(container => {
    // Fix role based on container name
    let role = container.role
    const name = container.name.toLowerCase()
    if (name.includes('traefik') || name.includes('nginx') || name.includes('caddy') || name.includes('haproxy')) {
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
      // Ensure capabilities are empty if not running
      capabilities: container.status === ContainerStatus.RUNNING ? container.capabilities : []
    }
  })

  const containerListGen = fc.array(containerGen, { minLength: 0, maxLength: 8 })

  const environmentFlagsGen = fc.record({
    backupEnabled: fc.boolean(),
    cronEnabled: fc.boolean(),
    pangolinEnabled: fc.boolean(),
    gerbilEnabled: fc.boolean(),
    proxyType: fc.constantFrom('traefik', 'nginx', 'caddy', 'haproxy', 'standalone', 'zoraxy'),
    customFlags: fc.dictionary(fc.string(), fc.boolean())
  })

  const apiResponseGen = fc.record({
    containers: containerListGen,
    proxyType: fc.option(fc.constantFrom('traefik', 'nginx', 'caddy', 'haproxy', 'standalone', 'zoraxy'), { nil: null }),
    environmentFlags: environmentFlagsGen
  })

  it('Property 10.1: Container detection should always return consistent results for the same input', () => {
    fc.assert(fc.asyncProperty(
      containerListGen,
      async (containers) => {
        // Mock API response
        const mockApiResponse = {
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

        vi.mocked(api.health.checkStack).mockResolvedValue(mockApiResponse)

        // Detect containers twice
        const result1 = await containerDetector.detectContainers()
        const result2 = await containerDetector.detectContainers()

        // Results should be identical
        expect(result1).toEqual(result2)
        expect(result1.length).toBe(containers.length)

        // Each container should have consistent properties
        result1.forEach((container, index) => {
          expect(container.name).toBe(containers[index].name)
          expect(container.running).toBe(containers[index].running)
          
          // Running containers should have capabilities, stopped ones should not
          if (container.running) {
            expect(container.capabilities.length).toBeGreaterThan(0)
            expect(container.capabilities).toContain('health')
          } else {
            expect(container.capabilities).toEqual([])
          }
        })
      }
    ), { numRuns: 50 })
  })

  it('Property 10.2: Feature availability should be deterministic based on container state', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, envFlags) => {
        const features = featureDetector.detectFeatures(containers, envFlags)
        
        // Feature availability should be consistent with container capabilities
        const runningContainers = containers.filter(c => c.running)
        const proxyContainers = runningContainers.filter(c => c.role === ContainerRole.PROXY)
        
        // Captcha should only be available if proxy containers support it
        const expectedCaptcha = proxyContainers.some(c => c.capabilities.includes('captcha'))
        expect(features.captcha).toBe(expectedCaptcha)
        
        // Backup should match environment flag
        expect(features.backup).toBe(envFlags.backupEnabled)
        
        // Cron jobs should match environment flag
        expect(features.cronJobs).toBe(envFlags.cronEnabled)
        
        // Proxy whitelist should be available if proxy containers support it
        const expectedWhitelist = proxyContainers.some(c => c.capabilities.includes('whitelist'))
        expect(features.whitelistProxy).toBe(expectedWhitelist)
        
        // Logs should be available if any container supports logs
        const expectedLogs = runningContainers.some(c => c.capabilities.includes('logs'))
        expect(features.logs).toBe(expectedLogs)
        
        // Pangolin should match environment and container presence
        const expectedPangolin = envFlags.pangolinEnabled && 
          runningContainers.some(c => c.name.toLowerCase().includes('pangolin'))
        expect(features.pangolin).toBe(expectedPangolin)
        
        // Gerbil should match environment and container presence
        const expectedGerbil = envFlags.gerbilEnabled && 
          runningContainers.some(c => c.name.toLowerCase().includes('gerbil'))
        expect(features.gerbil).toBe(expectedGerbil)
      }
    ), { numRuns: 100 })
  })

  it('Property 10.3: Deployment detection should handle unknown configurations gracefully', () => {
    fc.assert(fc.asyncProperty(
      fc.oneof(
        // Valid API responses
        apiResponseGen,
        // Invalid/error responses
        fc.constant({ error: 'API Error' }),
        fc.constant({ data: { success: false, error: 'Backend error' } }),
        fc.constant({ data: { success: true, data: null } })
      ),
      async (apiResponse) => {
        if ('error' in apiResponse) {
          // Mock API error
          vi.mocked(api.health.checkStack).mockRejectedValue(new Error(apiResponse.error))
        } else if (!apiResponse.data.success || !apiResponse.data.data) {
          // Mock API failure or null data
          vi.mocked(api.health.checkStack).mockResolvedValue(apiResponse)
        } else {
          // Mock successful response
          const mockResponse = {
            data: {
              success: true,
              data: {
                containers: apiResponse.containers.map(c => ({
                  name: c.name,
                  id: c.id,
                  status: c.status.toLowerCase(),
                  running: c.running
                }))
              }
            }
          }
          vi.mocked(api.health.checkStack).mockResolvedValue(mockResponse)
        }

        // Detection should not throw errors
        let detectionResult
        try {
          detectionResult = await containerDetector.detectContainers()
        } catch (error) {
          // If detection fails, it should provide meaningful error information
          expect(error).toBeInstanceOf(Error)
          expect((error as Error).message).toContain('Container detection failed')
          return // Test passes - graceful error handling
        }

        // If detection succeeds, result should be valid
        expect(Array.isArray(detectionResult)).toBe(true)
        detectionResult.forEach(container => {
          expect(typeof container.name).toBe('string')
          expect(typeof container.running).toBe('boolean')
          expect(Array.isArray(container.capabilities)).toBe(true)
          expect(Object.values(ContainerRole)).toContain(container.role)
        })
      }
    ), { numRuns: 30 })
  })

  it('Property 10.4: Environment detection should adapt to actual configuration', () => {
    fc.assert(fc.asyncProperty(
      fc.record({
        BACKUP_ENABLED: fc.option(fc.constantFrom('true', 'false', '1', '0', 'yes', 'no'), { nil: undefined }),
        CRON_ENABLED: fc.option(fc.constantFrom('true', 'false', '1', '0', 'yes', 'no'), { nil: undefined }),
        PANGOLIN_ENABLED: fc.option(fc.constantFrom('true', 'false'), { nil: undefined }),
        GERBIL_ENABLED: fc.option(fc.constantFrom('true', 'false'), { nil: undefined }),
        PROXY_TYPE: fc.option(fc.constantFrom('traefik', 'nginx', 'caddy', 'haproxy', 'standalone'), { nil: undefined }),
        COMPOSE_PROFILE: fc.option(fc.constantFrom('traefik', 'nginx', 'caddy'), { nil: undefined })
      }),
      async (envVars) => {
        // Filter out undefined values for the mock
        const cleanEnvVars = Object.fromEntries(
          Object.entries(envVars).filter(([_, value]) => value !== undefined)
        )

        // Mock environment variables API
        vi.mocked(api.validation.getEnvVars).mockResolvedValue({
          data: { success: true, data: cleanEnvVars }
        })

        const flags = await environmentDetector.readEnvironmentFlags()

        // Verify boolean parsing
        if (envVars.BACKUP_ENABLED !== undefined) {
          const expectedBackup = ['true', '1', 'yes', 'on'].includes(envVars.BACKUP_ENABLED.toLowerCase())
          expect(flags.backupEnabled).toBe(expectedBackup)
        } else {
          // Should use default value
          expect(typeof flags.backupEnabled).toBe('boolean')
        }

        if (envVars.CRON_ENABLED !== undefined) {
          const expectedCron = ['true', '1', 'yes', 'on'].includes(envVars.CRON_ENABLED.toLowerCase())
          expect(flags.cronEnabled).toBe(expectedCron)
        } else {
          // Should use default value
          expect(typeof flags.cronEnabled).toBe('boolean')
        }

        // Verify proxy type detection
        const expectedProxyType = envVars.PROXY_TYPE || envVars.COMPOSE_PROFILE || 'standalone'
        expect(flags.proxyType).toBe(expectedProxyType)

        // Flags should always be valid objects
        expect(typeof flags.backupEnabled).toBe('boolean')
        expect(typeof flags.cronEnabled).toBe('boolean')
        expect(typeof flags.pangolinEnabled).toBe('boolean')
        expect(typeof flags.gerbilEnabled).toBe('boolean')
        expect(typeof flags.proxyType).toBe('string')
        expect(typeof flags.customFlags).toBe('object')
      }
    ), { numRuns: 50 })
  })

  it('Property 10.5: Real-time updates should maintain consistency', () => {
    fc.assert(fc.asyncProperty(
      fc.array(containerListGen, { minLength: 1, maxLength: 3 }).filter(states => 
        states.length > 0 && states.some(containers => containers.length > 0)
      ),
      async (containerStates) => {
        let updateCount = 0
        const receivedUpdates: ContainerInfo[][] = []

        // Set up monitoring
        const cleanup = () => {
          // Cleanup function - in real implementation this would stop monitoring
        }

        try {
          // Simulate container state changes
          for (const containers of containerStates) {
            const mockResponse = {
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

            vi.mocked(api.health.checkStack).mockResolvedValue(mockResponse)
            const result = await containerDetector.detectContainers()
            
            updateCount++
            receivedUpdates.push([...result])
            
            // Small delay to allow async updates
            await new Promise(resolve => setTimeout(resolve, 1))
          }

          // Should have received updates for each state change
          expect(updateCount).toBeGreaterThan(0)
          expect(receivedUpdates.length).toBeGreaterThan(0)

          // Each update should be consistent with the corresponding container state
          receivedUpdates.forEach((update, index) => {
            if (index < containerStates.length) {
              expect(update.length).toBe(containerStates[index].length)
              update.forEach((container, containerIndex) => {
                if (containerIndex < containerStates[index].length) {
                  expect(container.name).toBe(containerStates[index][containerIndex].name)
                  expect(container.running).toBe(containerStates[index][containerIndex].running)
                }
              })
            }
          })
        } finally {
          cleanup()
        }
      }
    ), { numRuns: 10 })
  })
})