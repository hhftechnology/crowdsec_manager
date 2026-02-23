import { useEffect, useCallback } from 'react'

interface KeyBinding {
  /** Key to listen for (e.g., 'k', 'Escape', '/') */
  key: string
  /** Require Ctrl/Cmd modifier */
  ctrlOrMeta?: boolean
  /** Require Shift modifier */
  shift?: boolean
  /** Handler function */
  handler: (e: KeyboardEvent) => void
  /** Whether to prevent default browser behavior */
  preventDefault?: boolean
}

/**
 * Hook for managing keyboard shortcuts.
 * Automatically handles Ctrl (Windows/Linux) and Cmd (Mac).
 *
 * @param bindings - Array of key bindings to register
 * @param enabled - Whether shortcuts are active (default: true)
 */
export function useKeyboardNavigation(
  bindings: KeyBinding[],
  enabled = true
) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in inputs
      const target = e.target as HTMLElement
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        return
      }

      for (const binding of bindings) {
        const keyMatch = e.key.toLowerCase() === binding.key.toLowerCase()
        const ctrlMatch = binding.ctrlOrMeta
          ? e.ctrlKey || e.metaKey
          : !e.ctrlKey && !e.metaKey
        const shiftMatch = binding.shift ? e.shiftKey : !e.shiftKey

        if (keyMatch && ctrlMatch && shiftMatch) {
          if (binding.preventDefault !== false) {
            e.preventDefault()
          }
          binding.handler(e)
          return
        }
      }
    },
    [bindings]
  )

  useEffect(() => {
    if (!enabled) return

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [enabled, handleKeyDown])
}
