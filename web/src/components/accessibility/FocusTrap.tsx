/**
 * Focus Trap Component
 * Traps focus within a container for modals and dropdowns
 */

import React, { useEffect, useRef } from 'react'
import { FocusManager, KEYBOARD_KEYS } from '@/lib/accessibility'

interface FocusTrapProps {
  children: React.ReactNode
  active?: boolean
  restoreFocus?: boolean
  className?: string
}

export function FocusTrap({ 
  children, 
  active = true, 
  restoreFocus = true,
  className 
}: FocusTrapProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const previouslyFocusedElement = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (!active || !containerRef.current) return

    // Store the previously focused element
    previouslyFocusedElement.current = document.activeElement as HTMLElement

    // Focus the first focusable element in the container
    const firstFocusable = FocusManager.getFirstFocusableElement(containerRef.current)
    if (firstFocusable) {
      firstFocusable.focus()
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (!containerRef.current) return
      
      if (event.key === KEYBOARD_KEYS.TAB) {
        FocusManager.trapFocus(containerRef.current, event)
      }
    }

    document.addEventListener('keydown', handleKeyDown)

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      
      // Restore focus to the previously focused element
      if (restoreFocus && previouslyFocusedElement.current) {
        FocusManager.restoreFocus(previouslyFocusedElement.current)
      }
    }
  }, [active, restoreFocus])

  return (
    <div 
      ref={containerRef} 
      className={className}
      role="dialog"
      aria-modal={active ? "true" : undefined}
    >
      {children}
    </div>
  )
}

export default FocusTrap