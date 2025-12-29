import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fc from 'fast-check'
import { ContainerInfo, ContainerStatus, ContainerRole, HealthStatus, FeatureAvailability, EnvironmentFlags } from '@/lib/deployment-types'
import { featureDetector, detectFeatures, isFeatureSupported, canFeatureBeEnabled, getContainerDependentFeatures } from '@/lib/feature-detector'

/**
 * **Feature: proxy-aware-ui-components, Property 3: Capability-based feature availability**
 * **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
 */
describe('Capability-Based Features Properties', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // Generators for property-based testing
  const containerGen = fc.record({
    name: fc.constantFrom('traefik', 'nginx', 'caddy', 'haproxy', 'crowdsec', 'pangolin', 'gerbil', 'zoraxy'),
    id: fc.string({ minLength: 8, maxLength: 12 }),
    running: fc.boolean(),
    capabilities: fc.array(fc.constantFrom('whitelist', 'captcha', 'logs', 'bouncer', 'appsec', 'health'), { minLength: 0, maxLength: 6 }),
    role: fc.constantFrom(ContainerRole.PROXY, ContainerRole.SECURITY, ContainerRole.ADDON, ContainerRole.MONITORING),
    status: fc.constantFrom(ContainerStatus.RUNNING, ContainerStatus.STOPPED),
    healthStatus: fc.constantFrom(HealthStatus.HEALTHY, HealthStatus.UNHEALTHY)
  }).map(container => {
    // Fix role based on container name and ensure consistency
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
      running: container.status === ContainerStatus.RUNNING,
      capabilities: container.status === ContainerStatus.RUNNING 
        ? (container.capabilities.includes('health') ? container.capabilities : [...container.capabilities, 'health'])
        : []
    }
  })

  const containerListGen = fc.array(containerGen, { minLength: 0, maxLength: 5 })

  const environmentFlagsGen = fc.record({
    backupEnabled: fc.boolean(),
    cronEnabled: fc.boolean(),
    pangolinEnabled: fc.boolean(),
    gerbilEnabled: fc.boolean(),
    proxyType: fc.constantFrom('traefik', 'nginx', 'caddy', 'haproxy', 'standalone', 'zoraxy'),
    customFlags: fc.dictionary(fc.string(), fc.boolean())
  })

  it('Property 3.1: Features should only be available when supporting containers are present and running', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        const features = detectFeatures(containers, environment)
        const runningContainers = containers.filter(c => c.running)
        const proxyContainers = runningContainers.filter(c => c.role === ContainerRole.PROXY)

        // Captcha should only be available if proxy containers support it
        const expectedCaptcha = proxyContainers.some(c => c.capabilities.includes('captcha'))
        expect(features.captcha).toBe(expectedCaptcha)

        // Proxy whitelist should only be available if proxy containers support it
        const expectedWhitelistProxy = proxyContainers.some(c => c.capabilities.includes('whitelist'))
        expect(features.whitelistProxy).toBe(expectedWhitelistProxy)

        // AppSec should only be available if containers support it
        const expectedAppsec = runningContainers.some(c => c.capabilities.includes('appsec'))
        expect(features.appsec).toBe(expectedAppsec)

        // Bouncer should only be available if containers support it
        const expectedBouncer = runningContainers.some(c => c.capabilities.includes('bouncer'))
        expect(features.bouncer).toBe(expectedBouncer)

        // Logs should be available if any container supports logs
        const expectedLogs = runningContainers.some(c => c.capabilities.includes('logs'))
        expect(features.logs).toBe(expectedLogs)
      }
    ), { numRuns: 100 })
  })

  it('Property 3.2: Features should be disabled when required containers are not running', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        // Create a version where all containers are stopped
        const stoppedContainers = containers.map(c => ({
          ...c,
          running: false,
          status: ContainerStatus.STOPPED,
          capabilities: [] // Stopped containers have no capabilities
        }))

        const features = detectFeatures(stoppedContainers, environment)

        // Container-dependent features should be disabled
        expect(features.captcha).toBe(false)
        expect(features.whitelistProxy).toBe(false)
        expect(features.appsec).toBe(false)
        expect(features.bouncer).toBe(false)
        expect(features.logs).toBe(false)

        // Environment-dependent features should still match environment
        expect(features.backup).toBe(environment.backupEnabled)
        expect(features.cronJobs).toBe(environment.cronEnabled)
        
        // Addon features depend on both environment and container presence
        expect(features.pangolin).toBe(false) // No running containers
        expect(features.gerbil).toBe(false) // No running containers
      }
    ), { numRuns: 50 })
  })

  it('Property 3.3: Feature support detection should be consistent with feature availability', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        const deployment = { containers, environment, proxyType: environment.proxyType }
        const features = detectFeatures(containers, environment)

        // Test each feature
        Object.entries(features).forEach(([featureName, isAvailable]) => {
          const isSupported = isFeatureSupported(featureName, deployment)
          expect(isSupported).toBe(isAvailable)
        })

        // Test alternative feature names
        expect(isFeatureSupported('cron', deployment)).toBe(features.cronJobs)
        expect(isFeatureSupported('cronjobs', deployment)).toBe(features.cronJobs)
        expect(isFeatureSupported('whitelist', deployment)).toBe(features.whitelistProxy)
        expect(isFeatureSupported('whitelistproxy', deployment)).toBe(features.whitelistProxy)
      }
    ), { numRuns: 50 })
  })

  it('Property 3.4: Container capabilities should determine feature availability correctly', () => {
    fc.assert(fc.property(
      fc.record({
        containerName: fc.constantFrom('traefik', 'nginx', 'crowdsec'),
        capabilities: fc.array(fc.constantFrom('whitelist', 'captcha', 'logs', 'bouncer', 'appsec', 'health'), { minLength: 1, maxLength: 6 }),
        running: fc.boolean()
      }),
      environmentFlagsGen,
      ({ containerName, capabilities, running }, environment) => {
        // Create container with specific capabilities
        const container: ContainerInfo = {
          name: containerName,
          id: 'test-id',
          running,
          status: running ? ContainerStatus.RUNNING : ContainerStatus.STOPPED,
          capabilities: running ? capabilities : [],
          role: containerName === 'crowdsec' ? ContainerRole.SECURITY : ContainerRole.PROXY,
          healthStatus: running ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY
        }

        const features = detectFeatures([container], environment)

        if (running) {
          // Features should match capabilities
          if (capabilities.includes('captcha') && container.role === ContainerRole.PROXY) {
            expect(features.captcha).toBe(true)
          }
          
          if (capabilities.includes('whitelist') && container.role === ContainerRole.PROXY) {
            expect(features.whitelistProxy).toBe(true)
          }
          
          if (capabilities.includes('appsec')) {
            expect(features.appsec).toBe(true)
          }
          
          if (capabilities.includes('bouncer')) {
            expect(features.bouncer).toBe(true)
          }
          
          if (capabilities.includes('logs')) {
            expect(features.logs).toBe(true)
          }
        } else {
          // Stopped containers should not enable any capability-based features
          expect(features.captcha).toBe(false)
          expect(features.whitelistProxy).toBe(false)
          expect(features.appsec).toBe(false)
          expect(features.bouncer).toBe(false)
          expect(features.logs).toBe(false)
        }
      }
    ), { numRuns: 100 })
  })

  it('Property 3.5: Feature enablement possibility should be accurate', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        const deployment = { containers, environment, proxyType: environment.proxyType }
        const containerDeps = getContainerDependentFeatures()

        // Test container-dependent features
        Object.entries(containerDeps).forEach(([feature, requiredContainers]) => {
          const result = canFeatureBeEnabled(feature, deployment)
          const runningContainers = containers.filter(c => c.running)
          
          const hasRequiredContainer = requiredContainers.some(requiredContainer =>
            runningContainers.some(c => c.name.toLowerCase().includes(requiredContainer))
          )

          if (hasRequiredContainer) {
            expect(result.possible).toBe(true)
            expect(result.reason).toBe('Feature can be enabled')
          } else {
            expect(result.possible).toBe(false)
            expect(result.reason).toContain('Requires one of these containers')
          }
        })

        // Test environment-dependent features
        const envFeatures = ['backup', 'cronJobs', 'pangolin', 'gerbil']
        envFeatures.forEach(feature => {
          const result = canFeatureBeEnabled(feature, deployment)
          
          let shouldBeEnabled = true
          switch (feature) {
            case 'backup':
              shouldBeEnabled = environment.backupEnabled
              break
            case 'cronJobs':
              shouldBeEnabled = environment.cronEnabled
              break
            case 'pangolin':
              shouldBeEnabled = environment.pangolinEnabled
              break
            case 'gerbil':
              shouldBeEnabled = environment.gerbilEnabled
              break
          }

          if (shouldBeEnabled) {
            expect(result.possible).toBe(true)
          } else {
            expect(result.possible).toBe(false)
            expect(result.reason).toContain('environment variables')
          }
        })
      }
    ), { numRuns: 50 })
  })

  it('Property 3.6: Feature detection should be deterministic for the same input', () => {
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

        // Feature availability should be consistent
        Object.keys(result1).forEach(feature => {
          expect(result1[feature as keyof FeatureAvailability]).toBe(result2[feature as keyof FeatureAvailability])
          expect(result2[feature as keyof FeatureAvailability]).toBe(result3[feature as keyof FeatureAvailability])
        })
      }
    ), { numRuns: 50 })
  })
})