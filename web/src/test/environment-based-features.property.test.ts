import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fc from 'fast-check'
import { ContainerInfo, ContainerStatus, ContainerRole, HealthStatus, FeatureAvailability, EnvironmentFlags } from '@/lib/deployment-types'
import { featureDetector, detectFeatures, isFeatureSupported, getEnvironmentDependentFeatures } from '@/lib/feature-detector'

/**
 * **Feature: proxy-aware-ui-components, Property 6: Environment variable feature control**
 * **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
 */
describe('Environment-Based Feature Properties', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // Generators
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
      capabilities: container.status === ContainerStatus.RUNNING ? container.capabilities : []
    }
  })

  const containerListGen = fc.array(containerGen, { minLength: 0, maxLength: 5 })

  const environmentFlagsGen = fc.record({
    backupEnabled: fc.boolean(),
    cronEnabled: fc.boolean(),
    pangolinEnabled: fc.boolean(),
    gerbilEnabled: fc.boolean(),
    proxyType: fc.constantFrom('traefik', 'nginx', 'caddy', 'standalone'),
    customFlags: fc.dictionary(fc.string(), fc.boolean())
  })

  it('Property 6.1: Backup feature visibility should strictly follow environment configuration', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        const features = detectFeatures(containers, environment)
        
        // Req 4.1, 4.2
        expect(features.backup).toBe(environment.backupEnabled)
        expect(isFeatureSupported('backup', { containers, environment, proxyType: environment.proxyType })).toBe(environment.backupEnabled)
      }
    ), { numRuns: 100 })
  })

  it('Property 6.2: Cron jobs feature visibility should strictly follow environment configuration', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        const features = detectFeatures(containers, environment)
        
        // Req 4.3, 4.4
        expect(features.cronJobs).toBe(environment.cronEnabled)
        expect(isFeatureSupported('cron', { containers, environment, proxyType: environment.proxyType })).toBe(environment.cronEnabled)
        expect(isFeatureSupported('cronJobs', { containers, environment, proxyType: environment.proxyType })).toBe(environment.cronEnabled)
      }
    ), { numRuns: 100 })
  })

  it('Property 6.3: Addon features should require both environment flag AND container presence', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      (containers, environment) => {
        const features = detectFeatures(containers, environment)
        const deployment = { containers, environment, proxyType: environment.proxyType }
        
        const runningContainers = containers.filter(c => c.running)
        const hasPangolinContainer = runningContainers.some(c => c.name.toLowerCase().includes('pangolin'))
        const hasGerbilContainer = runningContainers.some(c => c.name.toLowerCase().includes('gerbil'))

        // Pangolin
        const expectedPangolin = environment.pangolinEnabled && hasPangolinContainer
        expect(features.pangolin).toBe(expectedPangolin)
        expect(isFeatureSupported('pangolin', deployment)).toBe(expectedPangolin)

        // Gerbil
        const expectedGerbil = environment.gerbilEnabled && hasGerbilContainer
        expect(features.gerbil).toBe(expectedGerbil)
        expect(isFeatureSupported('gerbil', deployment)).toBe(expectedGerbil)
      }
    ), { numRuns: 100 })
  })

  it('Property 6.4: Environment dependency mapping should be consistent with implementation', () => {
    fc.assert(fc.property(
      fc.constant(getEnvironmentDependentFeatures()),
      (envDeps) => {
        expect(envDeps.backup).toContain('BACKUP_ENABLED')
        expect(envDeps.cronJobs).toContain('CRON_ENABLED')
        expect(envDeps.pangolin).toContain('PANGOLIN_ENABLED')
        expect(envDeps.gerbil).toContain('GERBIL_ENABLED')
      }
    ))
  })

  it('Property 6.5: Feature support check should be insensitive to case', () => {
    fc.assert(fc.property(
      containerListGen,
      environmentFlagsGen,
      fc.constantFrom('BACKUP', 'backup', 'Backup', 'CRON', 'Cron', 'cron'),
      (containers, environment, featureBase) => {
        const deployment = { containers, environment, proxyType: environment.proxyType }
        
        const resultLower = isFeatureSupported(featureBase.toLowerCase(), deployment)
        const resultUpper = isFeatureSupported(featureBase.toUpperCase(), deployment)
        const resultMixed = isFeatureSupported(featureBase, deployment)
        
        expect(resultLower).toBe(resultMixed)
        expect(resultUpper).toBe(resultMixed)
      }
    ), { numRuns: 50 })
  })
})
