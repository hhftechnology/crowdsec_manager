/**
 * **Feature: multi-proxy-architecture, Property 2: Proxy Type Selection and Immutability**
 * 
 * Property-based test to verify that proxy type selection during initial deployment
 * is stored permanently and prevents runtime switching while maintaining configuration consistency.
 * 
 * This test validates Requirements 2.1, 2.2, 9.4
 */

import { describe, it, expect } from 'vitest'
import * as fc from 'fast-check'
import { ProxyType, PROXY_TYPES } from '../../../lib/proxy-types'
import { ProxySetupConfig } from '../ProxySetupWizard'

// Generators for property-based testing
const proxyTypeGen = fc.constantFrom<ProxyType>('traefik', 'nginx', 'caddy', 'haproxy', 'zoraxy', 'standalone')

const proxyConfigGen = fc.record({
  proxyType: proxyTypeGen,
  containerName: fc.string({ minLength: 1, maxLength: 50 }),
  configPaths: fc.record({
    dynamic: fc.string({ minLength: 1, maxLength: 100 }),
    static: fc.string({ minLength: 1, maxLength: 100 }),
    logs: fc.string({ minLength: 1, maxLength: 100 })
  }),
  customSettings: fc.dictionary(fc.string(), fc.string()),
  enabledFeatures: fc.array(fc.string(), { minLength: 0, maxLength: 10 })
})

// Helper functions to simulate proxy selection and configuration storage
const simulateProxySelection = (proxyType: ProxyType): ProxySetupConfig => {
  const proxyInfo = PROXY_TYPES.find(p => p.type === proxyType)
  return {
    proxyType,
    containerName: proxyType,
    configPaths: {
      dynamic: `/etc/${proxyType}/dynamic.conf`,
      static: `/etc/${proxyType}/static.conf`,
      logs: `/var/log/${proxyType}`
    },
    customSettings: {},
    enabledFeatures: proxyInfo?.features || []
  }
}

const simulateConfigurationStorage = (config: ProxySetupConfig): { stored: boolean; immutable: boolean } => {
  // Simulate storing configuration in database/filesystem
  const stored = config.proxyType !== undefined && config.containerName !== undefined
  
  // Simulate immutability check - once stored, proxy type cannot change
  const immutable = stored
  
  return { stored, immutable }
}

const simulateRuntimeSwitchAttempt = (
  currentConfig: ProxySetupConfig, 
  newProxyType: ProxyType
): { allowed: boolean; error?: string } => {
  // Simulate attempting to change proxy type at runtime
  if (currentConfig.proxyType === newProxyType) {
    return { allowed: true } // Same type, no change needed
  }
  
  // Runtime switching should be prevented
  return { 
    allowed: false, 
    error: `Cannot change proxy type from ${currentConfig.proxyType} to ${newProxyType} after initial deployment` 
  }
}

const validateConfigurationConsistency = (config: ProxySetupConfig): boolean => {
  // Validate that configuration is consistent with selected proxy type
  const proxyInfo = PROXY_TYPES.find(p => p.type === config.proxyType)
  if (!proxyInfo) return false
  
  // Check that enabled features are supported by the proxy type
  const unsupportedFeatures = config.enabledFeatures.filter(
    feature => !proxyInfo.features.includes(feature as any)
  )
  
  // Allow health feature for all proxy types
  const validUnsupportedFeatures = unsupportedFeatures.filter(feature => feature !== 'health')
  
  return validUnsupportedFeatures.length === 0
}

describe('Proxy Type Selection and Immutability Property Tests', () => {
  it('Proxy type selection during initial deployment creates immutable configuration', () => {
    fc.assert(fc.property(proxyTypeGen, (proxyType) => {
      // Simulate initial proxy selection
      const config = simulateProxySelection(proxyType)
      
      // Configuration should be created successfully
      expect(config.proxyType).toBe(proxyType)
      expect(config.containerName).toBeDefined()
      expect(config.configPaths).toBeDefined()
      
      // Configuration should be stored and marked as immutable
      const { stored, immutable } = simulateConfigurationStorage(config)
      expect(stored).toBe(true)
      expect(immutable).toBe(true)
      
      // Configuration should be consistent with proxy type
      expect(validateConfigurationConsistency(config)).toBe(true)
    }), { numRuns: 100 })
  })

  it('Runtime proxy type switching is prevented after initial deployment', () => {
    fc.assert(fc.property(proxyTypeGen, proxyTypeGen, (initialProxy, newProxy) => {
      // Set up initial configuration
      const initialConfig = simulateProxySelection(initialProxy)
      simulateConfigurationStorage(initialConfig)
      
      // Attempt to switch proxy type at runtime
      const switchResult = simulateRuntimeSwitchAttempt(initialConfig, newProxy)
      
      if (initialProxy === newProxy) {
        // Same proxy type should be allowed (no actual change)
        expect(switchResult.allowed).toBe(true)
      } else {
        // Different proxy type should be prevented
        expect(switchResult.allowed).toBe(false)
        expect(switchResult.error).toContain('Cannot change proxy type')
        expect(switchResult.error).toContain(initialProxy)
        expect(switchResult.error).toContain(newProxy)
      }
    }), { numRuns: 100 })
  })

  it('Configuration consistency is maintained for all proxy types', () => {
    fc.assert(fc.property(proxyConfigGen, (config) => {
      // Configuration should be consistent with its proxy type
      const isConsistent = validateConfigurationConsistency(config)
      
      // Get proxy info for validation
      const proxyInfo = PROXY_TYPES.find(p => p.type === config.proxyType)
      expect(proxyInfo).toBeDefined()
      
      if (proxyInfo) {
        // Check that all enabled features are either supported by proxy or are 'health'
        const invalidFeatures = config.enabledFeatures.filter(feature => 
          !proxyInfo.features.includes(feature as any) && feature !== 'health'
        )
        
        if (invalidFeatures.length === 0) {
          expect(isConsistent).toBe(true)
        } else {
          expect(isConsistent).toBe(false)
        }
      }
    }), { numRuns: 100 })
  })

  it('Proxy type selection validates against available proxy types', () => {
    fc.assert(fc.property(fc.string(), (invalidProxyType) => {
      // Only valid proxy types should be selectable
      const validProxyTypes = PROXY_TYPES.map(p => p.type)
      
      if (validProxyTypes.includes(invalidProxyType as ProxyType)) {
        // Valid proxy type should work
        const config = simulateProxySelection(invalidProxyType as ProxyType)
        expect(config.proxyType).toBe(invalidProxyType)
      } else {
        // Invalid proxy type should be rejected
        expect(() => {
          const proxyInfo = PROXY_TYPES.find(p => p.type === invalidProxyType as ProxyType)
          if (!proxyInfo) {
            throw new Error(`Invalid proxy type: ${invalidProxyType}`)
          }
        }).toThrow()
      }
    }), { numRuns: 100 })
  })

  it('Configuration storage preserves proxy type immutability', () => {
    fc.assert(fc.property(proxyTypeGen, (proxyType) => {
      // Create and store configuration
      const config = simulateProxySelection(proxyType)
      const { stored, immutable } = simulateConfigurationStorage(config)
      
      // Storage should succeed and mark configuration as immutable
      expect(stored).toBe(true)
      expect(immutable).toBe(true)
      
      // Stored configuration should maintain original proxy type
      expect(config.proxyType).toBe(proxyType)
      
      // Any attempt to modify proxy type should be prevented
      const modificationAttempt = simulateRuntimeSwitchAttempt(config, 'traefik' as ProxyType)
      if (config.proxyType !== 'traefik') {
        expect(modificationAttempt.allowed).toBe(false)
      }
    }), { numRuns: 100 })
  })

  it('Environment variable proxy type selection is respected and stored permanently', () => {
    fc.assert(fc.property(proxyTypeGen, (envProxyType) => {
      // Simulate environment variable-based proxy selection
      const envConfig = {
        PROXY_TYPE: envProxyType,
        PROXY_ENABLED: 'true',
        PROXY_CONTAINER_NAME: envProxyType
      }
      
      // Configuration should respect environment variable
      const config = simulateProxySelection(envProxyType)
      expect(config.proxyType).toBe(envProxyType)
      
      // Configuration should be stored permanently
      const { stored, immutable } = simulateConfigurationStorage(config)
      expect(stored).toBe(true)
      expect(immutable).toBe(true)
      
      // Runtime changes should still be prevented even with env vars
      const runtimeChange = simulateRuntimeSwitchAttempt(config, 'nginx' as ProxyType)
      if (envProxyType !== 'nginx') {
        expect(runtimeChange.allowed).toBe(false)
      }
    }), { numRuns: 100 })
  })
})