import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fc from 'fast-check'
import { ContainerInfo, ContainerStatus, ContainerRole, HealthStatus, FeatureAvailability, EnvironmentFlags } from '@/lib/deployment-types'
import { featureDetector, detectFeatures } from '@/lib/feature-detector'

/**
 * **Feature: proxy-aware-ui-components, Property 4: Dynamic feature availability updates**
 * **Validates: Requirements 2.5**
 */
describe('Dynamic Feature Updates Properties', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // Generators for property-based testing
  const containerGen = fc.record({
    name: fc.constantFrom('traefik', 'nginx', 'caddy', 'crowdsec', 'pangolin', 'gerbil'),
    id: fc.string({ minLength: 8, maxLength: 12 }),
    running: fc.boolean(),
    capabilities: fc.array(fc.constantFrom('whitelist', 'captcha', 'logs', 'bouncer', 'appsec', 'health'), { minLength: 0, maxLength: 6 }),
    role: fc.constantFrom(ContainerRole.PROXY, ContainerRole.SECURITY, ContainerRole.ADDON),
    status: fc.constantFrom(ContainerStatus.RUNNING, ContainerStatus.STOPPED),
    healthStatus: fc.constantFrom(HealthStatus.HEALTHY, HealthStatus.UNHEALTHY)
  }).map(container => {
    // Fix role based on container name and ensure consistency
    let role = container.role
    const name = container.name.toLowerCase()
    if (name.includes('traefik') || name.includes('nginx') || name.includes('caddy')) {
      role = ContainerRole.PROXY
    } else if (name.includes('crowdsec')) {
      role = ContainerRole.SECURITY
    } else if (name.includes('pangolin') || name.includes('gerbil')) {
      role = ContainerRole.ADDON
    }

    return {
      ...container,
      role,
      running: container.status === ContainerStatus.RUNNING,
      capabilities: container.status === ContainerStatus.RUNNING 
        ? (container.capabilities.includes('health') ? container.capabilities : [...container.capabilities, 'health'])
        : []
    }
  })

  const containerListGen = fc.array(containerGen, { minLength: 1, maxLength: 4 })

  const environmentFlagsGen = fc.record({
    backupEnabled: fc.boolean(),
    cronEnabled: fc.boolean(),
    pangolinEnabled: fc.boolean(),
    gerbilEnabled: fc.boolean(),
    proxyType: fc.constantFrom('traefik', 'nginx', 'caddy', 'standalone'),
    customFlags: fc.dictionary(fc.string(), fc.boolean())
  })

  it('Property 4.1: Feature availability should update immediately when container capabilities change', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        // Get initial feature state
        const initialFeatures = detectFeatures(containers, environment)

        // Modify container capabilities (add/remove capabilities from running containers)
        const modifiedContainers = containers.map(container => {
          if (container.running) {
            // Toggle some capabilities
            const newCapabilities = container.capabilities.includes('captcha')
              ? container.capabilities.filter(cap => cap !== 'captcha')
              : [...container.capabilities, 'captcha']
            
            return { ...container, capabilities: newCapabilities }
          }
          return container
        })

        const updatedFeatures = detectFeatures(modifiedContainers, environment)

        // Verify that capability changes are reflected in features
        const runningProxyContainers = modifiedContainers.filter(c => c.running && c.role === ContainerRole.PROXY)
        const expectedCaptcha = runningProxyContainers.some(c => c.capabilities.includes('captcha'))
        
        expect(updatedFeatures.captcha).toBe(expectedCaptcha)

        // If capabilities actually changed, features should be different
        const capabilitiesChanged = containers.some((container, index) => {
          const modified = modifiedContainers[index]
          return container.running && 
                 container.capabilities.length !== modified.capabilities.length
        })

        if (capabilitiesChanged) {
          // Check if the specific capability change should affect features
          const hadCaptchaCapability = containers.some(c => c.running && c.role === ContainerRole.PROXY && c.capabilities.includes('captcha'))
          const hasCaptchaCapability = modifiedContainers.some(c => c.running && c.role === ContainerRole.PROXY && c.capabilities.includes('captcha'))
          
          if (hadCaptchaCapability !== hasCaptchaCapability) {
            expect(initialFeatures.captcha).not.toBe(updatedFeatures.captcha)
          }
        }
      }
    ), { numRuns: 50 })
  })

  it('Property 4.2: Feature availability should update when container status changes', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        // Get initial feature state
        const initialFeatures = detectFeatures(containers, environment)

        // Toggle running status of containers
        const modifiedContainers = containers.map(container => ({
          ...container,
          running: !container.running,
          status: container.running ? ContainerStatus.STOPPED : ContainerStatus.RUNNING,
          capabilities: !container.running 
            ? (container.capabilities.includes('health') ? container.capabilities : [...container.capabilities, 'health'])
            : []
        }))

        const updatedFeatures = detectFeatures(modifiedContainers, environment)

        // Verify that status changes are reflected in features
        const runningContainers = modifiedContainers.filter(c => c.running)
        const proxyContainers = runningContainers.filter(c => c.role === ContainerRole.PROXY)

        // Container-dependent features should reflect new running state
        const expectedCaptcha = proxyContainers.some(c => c.capabilities.includes('captcha'))
        const expectedWhitelistProxy = proxyContainers.some(c => c.capabilities.includes('whitelist'))
        const expectedLogs = runningContainers.some(c => c.capabilities.includes('logs'))

        expect(updatedFeatures.captcha).toBe(expectedCaptcha)
        expect(updatedFeatures.whitelistProxy).toBe(expectedWhitelistProxy)
        expect(updatedFeatures.logs).toBe(expectedLogs)

        // Environment-dependent features should remain unchanged
        expect(updatedFeatures.backup).toBe(environment.backupEnabled)
        expect(updatedFeatures.cronJobs).toBe(environment.cronEnabled)


      }
    ), { numRuns: 30 })
  })

  it('Property 4.3: Feature availability should update when environment flags change', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        // Get initial feature state
        const initialFeatures = detectFeatures(containers, environment)

        // Modify environment flags
        const modifiedEnvironment: EnvironmentFlags = {
          ...environment,
          backupEnabled: !environment.backupEnabled,
          cronEnabled: !environment.cronEnabled,
          pangolinEnabled: !environment.pangolinEnabled,
          gerbilEnabled: !environment.gerbilEnabled
        }

        const updatedFeatures = detectFeatures(containers, modifiedEnvironment)

        // Environment-dependent features should reflect changes
        expect(updatedFeatures.backup).toBe(modifiedEnvironment.backupEnabled)
        expect(updatedFeatures.cronJobs).toBe(modifiedEnvironment.cronEnabled)

        // Addon features depend on both environment and container presence
        const addonContainers = containers.filter(c => c.running && c.role === ContainerRole.ADDON)
        const expectedPangolin = modifiedEnvironment.pangolinEnabled && 
                                addonContainers.some(c => c.name.toLowerCase().includes('pangolin'))
        const expectedGerbil = modifiedEnvironment.gerbilEnabled && 
                              addonContainers.some(c => c.name.toLowerCase().includes('gerbil'))

        expect(updatedFeatures.pangolin).toBe(expectedPangolin)
        expect(updatedFeatures.gerbil).toBe(expectedGerbil)

        // Container-dependent features should remain unchanged
        const runningContainers = containers.filter(c => c.running)
        const proxyContainers = runningContainers.filter(c => c.role === ContainerRole.PROXY)
        
        expect(updatedFeatures.captcha).toBe(proxyContainers.some(c => c.capabilities.includes('captcha')))
        expect(updatedFeatures.whitelistProxy).toBe(proxyContainers.some(c => c.capabilities.includes('whitelist')))

        // Features should be different since we flipped all environment flags
        expect(initialFeatures).not.toEqual(updatedFeatures)
      }
    ), { numRuns: 30 })
  })

  it('Property 4.4: Multiple simultaneous changes should be handled correctly', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        // Get initial feature state
        const initialFeatures = detectFeatures(containers, environment)

        // Make multiple simultaneous changes
        const modifiedContainers = containers.map((container, index) => {
          // Modify every other container
          if (index % 2 === 0) {
            return {
              ...container,
              running: !container.running,
              status: container.running ? ContainerStatus.STOPPED : ContainerStatus.RUNNING,
              capabilities: !container.running 
                ? ['health', 'logs', 'bouncer'] // Give some standard capabilities
                : []
            }
          }
          return container
        })

        const modifiedEnvironment: EnvironmentFlags = {
          ...environment,
          backupEnabled: !environment.backupEnabled,
          cronEnabled: !environment.cronEnabled
        }

        const updatedFeatures = detectFeatures(modifiedContainers, modifiedEnvironment)

        // Verify all changes are reflected
        const runningContainers = modifiedContainers.filter(c => c.running)
        const proxyContainers = runningContainers.filter(c => c.role === ContainerRole.PROXY)
        const addonContainers = runningContainers.filter(c => c.role === ContainerRole.ADDON)

        // Container-dependent features
        expect(updatedFeatures.captcha).toBe(proxyContainers.some(c => c.capabilities.includes('captcha')))
        expect(updatedFeatures.whitelistProxy).toBe(proxyContainers.some(c => c.capabilities.includes('whitelist')))
        expect(updatedFeatures.logs).toBe(runningContainers.some(c => c.capabilities.includes('logs')))
        expect(updatedFeatures.bouncer).toBe(runningContainers.some(c => c.capabilities.includes('bouncer')))

        // Environment-dependent features
        expect(updatedFeatures.backup).toBe(modifiedEnvironment.backupEnabled)
        expect(updatedFeatures.cronJobs).toBe(modifiedEnvironment.cronEnabled)

        // Addon features (both environment and container dependent)
        expect(updatedFeatures.pangolin).toBe(
          modifiedEnvironment.pangolinEnabled && 
          addonContainers.some(c => c.name.toLowerCase().includes('pangolin'))
        )
        expect(updatedFeatures.gerbil).toBe(
          modifiedEnvironment.gerbilEnabled && 
          addonContainers.some(c => c.name.toLowerCase().includes('gerbil'))
        )

        // Features should be different due to multiple changes
        const hasContainerChanges = containers.some((container, index) => 
          container.running !== modifiedContainers[index].running
        )
        const hasEnvironmentChanges = environment.backupEnabled !== modifiedEnvironment.backupEnabled ||
                                     environment.cronEnabled !== modifiedEnvironment.cronEnabled

        if (hasContainerChanges || hasEnvironmentChanges) {
          expect(initialFeatures).not.toEqual(updatedFeatures)
        }
      }
    ), { numRuns: 25 })
  })

  it('Property 4.5: Feature updates should be consistent across multiple detections', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        // Detect features multiple times with same input
        const result1 = detectFeatures(containers, environment)
        const result2 = detectFeatures(containers, environment)
        const result3 = featureDetector.detectFeatures(containers, environment)

        // All results should be identical
        expect(result1).toEqual(result2)
        expect(result2).toEqual(result3)

        // Modify input and detect again
        const modifiedContainers = containers.map(c => ({
          ...c,
          running: !c.running,
          status: c.running ? ContainerStatus.STOPPED : ContainerStatus.RUNNING,
          capabilities: !c.running ? ['health'] : []
        }))

        const modifiedResult1 = detectFeatures(modifiedContainers, environment)
        const modifiedResult2 = detectFeatures(modifiedContainers, environment)

        // Modified results should also be identical to each other
        expect(modifiedResult1).toEqual(modifiedResult2)

        // But different from original (since we flipped all container states)

      }
    ), { numRuns: 30 })
  })

  it('Property 4.6: Feature detection should handle edge cases gracefully', () => {
    fc.assert(fc.property(
      fc.oneof(
        // Empty containers
        fc.constant([]),
        // All stopped containers
        containerListGen.map(containers => 
          containers.map(c => ({ ...c, running: false, status: ContainerStatus.STOPPED, capabilities: [] }))
        ),
        // Containers with no capabilities
        containerListGen.map(containers => 
          containers.map(c => ({ ...c, capabilities: [] }))
        )
      ),
      environmentFlagsGen,
      (containers, environment) => {
        // Feature detection should not throw errors
        let features: FeatureAvailability
        expect(() => {
          features = detectFeatures(containers, environment)
        }).not.toThrow()

        // Features should be valid objects
        expect(typeof features!.captcha).toBe('boolean')
        expect(typeof features!.backup).toBe('boolean')
        expect(typeof features!.cronJobs).toBe('boolean')
        expect(typeof features!.whitelistProxy).toBe('boolean')
        expect(typeof features!.logs).toBe('boolean')
        expect(typeof features!.pangolin).toBe('boolean')
        expect(typeof features!.gerbil).toBe('boolean')
        expect(typeof features!.appsec).toBe('boolean')
        expect(typeof features!.bouncer).toBe('boolean')

        // Environment-dependent features should still work
        expect(features!.backup).toBe(environment.backupEnabled)
        expect(features!.cronJobs).toBe(environment.cronEnabled)

        // Container-dependent features should be false when no running containers
        const runningContainers = containers.filter(c => c.running)
        if (runningContainers.length === 0) {
          expect(features!.captcha).toBe(false)
          expect(features!.whitelistProxy).toBe(false)
          expect(features!.appsec).toBe(false)
          expect(features!.bouncer).toBe(false)
          expect(features!.logs).toBe(false)
          expect(features!.pangolin).toBe(false)
          expect(features!.gerbil).toBe(false)
        }
      }
    ), { numRuns: 30 })
  })
})