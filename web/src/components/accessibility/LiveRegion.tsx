/**
 * Live Region Component
 * Provides screen reader announcements for dynamic content changes
 */

import { useEffect, useRef } from 'react'
import { ARIA_LIVE_PRIORITIES } from '@/lib/accessibility'

interface LiveRegionProps {
  message?: string
  priority?: keyof typeof ARIA_LIVE_PRIORITIES
  atomic?: boolean
  className?: string
}

export function LiveRegion({ 
  message = '', 
  priority = 'POLITE',
  atomic = true,
  className = 'sr-only'
}: LiveRegionProps) {
  const regionRef = useRef<HTMLDivElement>(null)
  const timeoutRef = useRef<number>()

  useEffect(() => {
    if (!message || !regionRef.current) return

    // Clear any existing timeout
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }

    // Clear the region first to ensure screen readers pick up the change
    regionRef.current.textContent = ''

    // Set the message after a brief delay
    timeoutRef.current = setTimeout(() => {
      if (regionRef.current) {
        regionRef.current.textContent = message
      }
    }, 100)

    // Clear the message after announcement
    const clearTimeoutId = setTimeout(() => {
      if (regionRef.current) {
        regionRef.current.textContent = ''
      }
    }, 1000)

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
      clearTimeout(clearTimeoutId)
    }
  }, [message])

  return (
    <div
      ref={regionRef}
      aria-live={ARIA_LIVE_PRIORITIES[priority]}
      aria-atomic={atomic}
      className={className}
      role="status"
    />
  )
}

export default LiveRegion