import { useState, useCallback } from 'react'
import { useKeyboardNavigation } from './useKeyboardNavigation'

/**
 * Hook for managing command palette open/close state
 * with Cmd+K / Ctrl+K keyboard shortcut.
 */
export function useCommandPalette() {
  const [open, setOpen] = useState(false)

  const toggle = useCallback(() => setOpen((prev) => !prev), [])

  useKeyboardNavigation([
    {
      key: 'k',
      ctrlOrMeta: true,
      handler: () => toggle(),
    },
  ])

  return {
    open,
    setOpen,
    toggle,
  }
}
