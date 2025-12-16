import { useState, useEffect } from 'react'

/**
 * Custom hook for responsive design using CSS media queries
 * Returns true if the media query matches the current viewport
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(false)

  useEffect(() => {
    // Check if window is available (client-side)
    if (typeof window === 'undefined') {
      return
    }

    const mediaQuery = window.matchMedia(query)
    
    // Set initial value
    setMatches(mediaQuery.matches)

    // Create event listener
    const handleChange = (event: MediaQueryListEvent) => {
      setMatches(event.matches)
    }

    // Add listener
    mediaQuery.addEventListener('change', handleChange)

    // Cleanup
    return () => {
      mediaQuery.removeEventListener('change', handleChange)
    }
  }, [query])

  return matches
}

/**
 * Predefined breakpoint hooks for common responsive patterns
 */
export const useBreakpoints = () => {
  const isMobile = useMediaQuery('(max-width: 768px)')
  const isTablet = useMediaQuery('(min-width: 769px) and (max-width: 1024px)')
  const isDesktop = useMediaQuery('(min-width: 1025px)')
  const isLargeDesktop = useMediaQuery('(min-width: 1440px)')
  
  // Touch device detection
  const isTouchDevice = useMediaQuery('(hover: none) and (pointer: coarse)')
  
  // Orientation detection
  const isLandscape = useMediaQuery('(orientation: landscape)')
  const isPortrait = useMediaQuery('(orientation: portrait)')
  
  // High DPI detection
  const isHighDPI = useMediaQuery('(min-resolution: 2dppx)')

  return {
    isMobile,
    isTablet,
    isDesktop,
    isLargeDesktop,
    isTouchDevice,
    isLandscape,
    isPortrait,
    isHighDPI,
    // Convenience combinations
    isMobileOrTablet: isMobile || isTablet,
    isTabletOrDesktop: isTablet || isDesktop
  }
}