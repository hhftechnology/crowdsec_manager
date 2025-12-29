import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fc from 'fast-check'
import { ContainerInfo, ContainerStatus, ContainerRole, HealthStatus } from '@/contexts/DeploymentContext'
import { containerDetector, getRunningContainers, getContainersByRole } from '@/lib/container-detector'
import api from '@/lib/api'

// Mock the API
vi.mock('@/lib/api', () => ({
  default: {
    health: {
      checkStack: vi.fn()
    }
  }
}))

/**
 * **Feature: proxy-aware-ui-components, Property 1: Container-based UI visibility**
 * **Validates: Requirements 1.1, 1.2, 1.3, 1.4**
 */
describe('Container Visibility Properties', () => {
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
      // Ensure capabilities are empty if not running, and include health if running
      capabilities: container.status === ContainerStatus.RUNNING 
        ? (container.capabilities.includes('health') ? container.capabilities : [...container.capabilities, 'health'])
        : []
    }
  })

  const containerListGen = fc.array(containerGen, { minLength: 0, maxLength: 8 })

  it('Property 1.1: Only running containers should be visible in UI displays', () => {
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

        // Get all containers and running containers
        const allContainers = await containerDetector.detectContainers()
        const runningContainers = await getRunningContainers()

        // All containers in runningContainers should have running = true
        runningContainers.forEach(container => {
          expect(container.running).toBe(true)
          expect(container.status).toBe(ContainerStatus.RUNNING)
        })

        // Running containers should be a subset of all containers
        expect(runningContainers.length).toBeLessThanOrEqual(allContainers.length)

        // Every running container should exist in all containers
        runningContainers.forEach(runningContainer => {
          const exists = allContainers.some(c => 
            c.name === runningContainer.name && c.running === true
          )
          expect(exists).toBe(true)
        })

        // Count should match expected running containers
        const expectedRunningCount = containers.filter(c => c.running).length
        expect(runningContainers.length).toBe(expectedRunningCount)
      }
    ), { numRuns: 100 })
  })

  it('Property 1.2: Absent containers should be hidden from all UI elements', () => {
    fc.assert(fc.asyncProperty(
      containerListGen,
      fc.array(fc.string({ minLength: 3, maxLength: 10 }), { minLength: 1, maxLength: 5 }),
      async (presentContainers, absentContainerNames) => {
        // Mock API response with only present containers
        const mockApiResponse = {
          data: {
            success: true,
            data: {
              containers: presentContainers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.status.toLowerCase(),
                running: c.running
              }))
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(mockApiResponse)

        const detectedContainers = await containerDetector.detectContainers()

        // None of the absent container names should appear in detected containers
        absentContainerNames.forEach(absentName => {
          const found = detectedContainers.some(c => c.name === absentName)
          expect(found).toBe(false)
        })

        // Only present containers should be detected
        detectedContainers.forEach(container => {
          const isPresent = presentContainers.some(c => c.name === container.name)
          expect(isPresent).toBe(true)
        })

        // Count should match exactly
        expect(detectedContainers.length).toBe(presentContainers.length)
      }
    ), { numRuns: 50 })
  })

  it('Property 1.3: Container grouping by role should be consistent', () => {
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

        const containersByRole = await getContainersByRole()

        // All role categories should exist
        expect(containersByRole).toHaveProperty(ContainerRole.PROXY)
        expect(containersByRole).toHaveProperty(ContainerRole.SECURITY)
        expect(containersByRole).toHaveProperty(ContainerRole.ADDON)
        expect(containersByRole).toHaveProperty(ContainerRole.MONITORING)

        // Each container should be in exactly one role category
        const allGroupedContainers = [
          ...containersByRole[ContainerRole.PROXY],
          ...containersByRole[ContainerRole.SECURITY],
          ...containersByRole[ContainerRole.ADDON],
          ...containersByRole[ContainerRole.MONITORING]
        ]

        const allDetectedContainers = await containerDetector.detectContainers()
        expect(allGroupedContainers.length).toBe(allDetectedContainers.length)

        // Verify role assignments are correct
        Object.entries(containersByRole).forEach(([role, roleContainers]) => {
          roleContainers.forEach(container => {
            expect(container.role).toBe(role)
            
            // Verify role matches container name patterns
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
      }
    ), { numRuns: 50 })
  })

  it('Property 1.4: Running containers should have capabilities, stopped ones should not', () => {
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

        const detectedContainers = await containerDetector.detectContainers()

        detectedContainers.forEach(container => {
          if (container.running) {
            // Running containers should have at least the 'health' capability
            expect(container.capabilities.length).toBeGreaterThan(0)
            expect(container.capabilities).toContain('health')
            
            // Capabilities should be appropriate for the container type
            const name = container.name.toLowerCase()
            if (name.includes('traefik')) {
              expect(container.capabilities).toEqual(
                expect.arrayContaining(['health', 'whitelist', 'captcha', 'logs', 'bouncer', 'appsec'])
              )
            } else if (name.includes('nginx') || name.includes('caddy') || name.includes('haproxy')) {
              expect(container.capabilities).toEqual(
                expect.arrayContaining(['health', 'whitelist', 'logs', 'bouncer'])
              )
            } else if (name.includes('crowdsec')) {
              expect(container.capabilities).toEqual(
                expect.arrayContaining(['health', 'bouncer', 'logs'])
              )
            }
          } else {
            // Stopped containers should have no capabilities
            expect(container.capabilities).toEqual([])
          }
        })
      }
    ), { numRuns: 100 })
  })

  it('Property 1.5: Container visibility should be deterministic for the same input', () => {
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

        // Get containers multiple times
        const result1 = await containerDetector.detectContainers()
        const result2 = await containerDetector.detectContainers()
        const result3 = await getRunningContainers()
        const result4 = await getRunningContainers()

        // Results should be identical
        expect(result1).toEqual(result2)
        expect(result3).toEqual(result4)

        // Running containers should be consistent subset
        const runningFromAll1 = result1.filter(c => c.running)
        const runningFromAll2 = result2.filter(c => c.running)
        
        expect(runningFromAll1).toEqual(result3)
        expect(runningFromAll2).toEqual(result4)
        expect(result3).toEqual(result4)
      }
    ), { numRuns: 50 })
  })
})