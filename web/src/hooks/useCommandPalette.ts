import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { ProxyType, Feature } from '@/lib/proxy-types'

interface CommandPaletteState {
  isOpen: boolean
  query: string
}

interface UseCommandPaletteProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
}

export function useCommandPalette({ proxyType, supportedFeatures }: UseCommandPaletteProps) {
  const [state, setState] = useState<CommandPaletteState>({
    isOpen: false,
    query: ''
  })
  const navigate = useNavigate()

  // Open/close command palette
  const toggle = useCallback(() => {
    setState(prev => ({ ...prev, isOpen: !prev.isOpen }))
  }, [])

  const open = useCallback(() => {
    setState(prev => ({ ...prev, isOpen: true }))
  }, [])

  const close = useCallback(() => {
    setState(prev => ({ ...prev, isOpen: false, query: '' }))
  }, [])

  // Set search query
  const setQuery = useCallback((query: string) => {
    setState(prev => ({ ...prev, query }))
  }, [])

  // Execute command and close palette
  const executeCommand = useCallback((href: string) => {
    close()
    navigate(href)
  }, [close, navigate])

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Cmd/Ctrl + K to toggle
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        toggle()
      }
      
      // Escape to close
      if (e.key === 'Escape' && state.isOpen) {
        e.preventDefault()
        close()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [toggle, close, state.isOpen])

  // Generate contextual commands based on current proxy
  const getContextualCommands = useCallback(() => {
    const commands = []

    // Always available commands
    commands.push(
      { id: 'dashboard', label: 'Go to Dashboard', href: '/', keywords: ['dashboard', 'home'] },
      { id: 'health', label: 'Check System Health', href: '/health', keywords: ['health', 'status'] },
      { id: 'decisions', label: 'View Security Decisions', href: '/decisions', keywords: ['decisions', 'security'] },
      { id: 'alerts', label: 'View Security Alerts', href: '/alerts', keywords: ['alerts', 'threats'] }
    )

    // Proxy-specific commands
    if (supportedFeatures.includes('whitelist')) {
      commands.push({
        id: 'whitelist',
        label: 'Manage Proxy Whitelist',
        href: '/proxy-whitelist',
        keywords: ['whitelist', 'allow', 'ip']
      })
    }

    if (supportedFeatures.includes('captcha')) {
      commands.push({
        id: 'captcha',
        label: 'Configure Captcha Protection',
        href: '/captcha',
        keywords: ['captcha', 'protection', 'security']
      })
    }

    if (supportedFeatures.includes('logs')) {
      commands.push({
        id: 'logs',
        label: `View ${proxyType.charAt(0).toUpperCase() + proxyType.slice(1)} Logs`,
        href: '/proxy-logs',
        keywords: ['logs', 'access', proxyType]
      })
    }

    return commands
  }, [proxyType, supportedFeatures])

  return {
    isOpen: state.isOpen,
    query: state.query,
    toggle,
    open,
    close,
    setQuery,
    executeCommand,
    getContextualCommands
  }
}