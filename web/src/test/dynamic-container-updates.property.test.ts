import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fc from 'fast-check'
import { ContainerInfo, ContainerStatus, ContainerRole, HealthStatus } from '@/contexts/DeploymentContext'
import { containerDetector } from '@/lib/container-detector'
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
 * **Feature: proxy-aware-ui-components, Property 2: Dynamic container status updates**
 * **Validates: Requirements 1.5**
 */
describe('Dynamic Container Updates Properties', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('Property 2.1: Container status changes should be reflected immediately', () => {
    fc.assert(fc.asyncProperty(
      fc.array(fc.record({
        name: fc.constantFrom('traefik', 'nginx', 'crowdsec'),
        id: fc.string({ minLength: 8, maxLength: 12 }),
        running: fc.boolean()
      }), { minLength: 1, maxLength: 3 }),
      async (containers) => {
        // Mock initial state
        const initialMockResponse = {
          data: {
            success: true,
            data: {
              containers: containers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.running ? 'running' : 'stopped',
                running: c.running
              }))
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(initialMockResponse)
        const initialResult = await containerDetector.detectContainers()

        // Create updated state with flipped running status
        const updatedContainers = containers.map(c => ({
          ...c,
          running: !c.running
        }))

        const updatedMockResponse = {
          data: {
            success: true,
            data: {
              containers: updatedContainers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.running ? 'running' : 'stopped',
                running: c.running
              }))
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(updatedMockResponse)
        const updatedResult = await containerDetector.detectContainers()

        // Verify that changes are reflected
        expect(updatedResult.length).toBe(containers.length)
        
        updatedResult.forEach((container, index) => {
          expect(container.name).toBe(updatedContainers[index].name)
          expect(container.running).toBe(updatedContainers[index].running)
          
          // If container is now running, it should have capabilities
          if (updatedContainers[index].running) {
            expect(container.capabilities.length).toBeGreaterThan(0)
            expect(container.capabilities).toContain('health')
          } else {
            expect(container.capabilities).toEqual([])
          }
        })

        // Results should be different since we flipped all running states
        expect(initialResult).not.toEqual(updatedResult)
      }
    ), { numRuns: 20 })
  })

  it('Property 2.2: Container additions should be detected immediately', () => {
    fc.assert(fc.asyncProperty(
      fc.record({
        initial: fc.array(fc.record({
          name: fc.constantFrom('traefik', 'nginx'),
          id: fc.string({ minLength: 8, maxLength: 12 }),
          running: fc.boolean()
        }), { minLength: 0, maxLength: 2 }),
        newContainer: fc.record({
          name: fc.constantFrom('crowdsec', 'pangolin'),
          id: fc.string({ minLength: 8, maxLength: 12 }),
          running: fc.boolean()
        })
      }),
      async ({ initial, newContainer }) => {
        // Mock initial state
        const initialMockResponse = {
          data: {
            success: true,
            data: {
              containers: initial.map(c => ({
                name: c.name,
                id: c.id,
                status: c.running ? 'running' : 'stopped',
                running: c.running
              }))
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(initialMockResponse)
        const initialResult = await containerDetector.detectContainers()

        // Mock state with new container added
        const updatedContainers = [...initial, newContainer]
        const updatedMockResponse = {
          data: {
            success: true,
            data: {
              containers: updatedContainers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.running ? 'running' : 'stopped',
                running: c.running
              }))
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(updatedMockResponse)
        const updatedResult = await containerDetector.detectContainers()

        // Verify container was added
        expect(updatedResult.length).toBe(initialResult.length + 1)
        
        // Verify new container is present
        const addedContainer = updatedResult.find(c => c.name === newContainer.name)
        expect(addedContainer).toBeDefined()
        expect(addedContainer!.running).toBe(newContainer.running)
      }
    ), { numRuns: 15 })
  })

  it('Property 2.3: Update detection should be consistent', () => {
    fc.assert(fc.asyncProperty(
      fc.array(fc.record({
        name: fc.constantFrom('traefik', 'crowdsec'),
        id: fc.string({ minLength: 8, maxLength: 12 }),
        running: fc.boolean()
      }), { minLength: 1, maxLength: 2 }),
      async (containers) => {
        // Mock state
        const mockResponse = {
          data: {
            success: true,
            data: {
              containers: containers.map(c => ({
                name: c.name,
                id: c.id,
                status: c.running ? 'running' : 'stopped',
                running: c.running
              }))
            }
          }
        }

        vi.mocked(api.health.checkStack).mockResolvedValue(mockResponse)
        
        // Get state multiple times
        const result1 = await containerDetector.detectContainers()
        const result2 = await containerDetector.detectContainers()
        
        // Results should be identical
        expect(result1).toEqual(result2)
        expect(result1.length).toBe(containers.length)
      }
    ), { numRuns: 20 })
  })
})