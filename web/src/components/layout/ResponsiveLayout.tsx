import { ReactNode, useState, useEffect, useCallback, useMemo, memo } from 'react'
import { cn } from '@/lib/utils'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { AppShell } from './AppShell'
import { AppSidebar } from './AppSidebar'
import { AppHeader } from './AppHeader'

interface ResponsiveLayoutProps {
  children: ReactNode
  className?: string
}

/**
 * ResponsiveLayout - Complete responsive layout system
 * Integrates AppShell, AppSidebar, and AppHeader with enhanced responsive behavior,
 * keyboard navigation, and mobile optimizations for mobile, tablet, and desktop viewports
 * 
 * Performance optimizations:
 * - Memoized class calculations to prevent unnecessary re-renders
 * - Callback memoization for event handlers
 * - Optimized event listener management
 */
export const ResponsiveLayout = memo(function ResponsiveLayout({ children, className }: ResponsiveLayoutProps) {
  const [isCollapsed, setIsCollapsed] = useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  
  const { isMobile, isTablet, isDesktop, isPortrait, needsTouchOptimization } = useBreakpoints()

  // Memoize responsive classes to prevent unnecessary recalculations
  const responsiveClasses = useMemo(() => ({
    mainContent: cn(
      "transition-all duration-300",
      // Responsive padding with touch-friendly spacing
      isMobile ? (needsTouchOptimization ? "p-4" : "p-3") : isTablet ? "p-5" : "p-6",
      // Safe area padding for devices with notches/home indicators
      isMobile && "pb-safe-area-inset-bottom",
      // Ensure proper scrolling behavior on mobile
      isMobile && "overscroll-behavior-y-contain"
    ),
    container: cn(
      "mx-auto w-full",
      // Responsive max-width with better breakpoint handling
      isMobile ? "max-w-full" : 
      isTablet ? "max-w-4xl" : 
      "max-w-7xl"
    ),
    footer: cn(
      "border-t text-center text-xs text-muted-foreground bg-background transition-all",
      // Hide on mobile portrait, show on landscape and larger screens
      isMobile && isPortrait ? "hidden" : "p-4",
      // Add safe area padding on mobile landscape
      isMobile && !isPortrait && "pb-safe-area-inset-bottom"
    ),
    footerContent: cn(
      "flex gap-2",
      // Stack vertically on mobile, horizontally on larger screens
      isMobile ? "flex-col items-center" : "flex-row justify-between items-center"
    ),
    footerLinks: cn(
      "flex gap-2",
      isMobile ? "flex-col items-center text-center" : "flex-row gap-4"
    ),
    sidebar: cn(
      "transition-all duration-300 ease-in-out z-50",
      // Mobile: slide in from left as overlay
      isMobile && [
        "fixed inset-y-0 left-0",
        isMobileMenuOpen ? "translate-x-0" : "-translate-x-full"
      ],
      // Tablet/Desktop: normal sidebar behavior
      !isMobile && "relative"
    )
  }), [isMobile, isTablet, isDesktop, isPortrait, needsTouchOptimization, isMobileMenuOpen])

  // Memoize the current year to prevent recalculation on every render
  const currentYear = useMemo(() => new Date().getFullYear(), [])

  // Auto-collapse sidebar based on viewport and orientation
  useEffect(() => {
    if (isMobile) {
      setIsCollapsed(true)
      setIsMobileMenuOpen(false)
    } else if (isTablet) {
      // On tablet, consider orientation for better UX
      setIsCollapsed(isPortrait ? true : false)
    } else if (isDesktop) {
      setIsCollapsed(false)
    }
  }, [isMobile, isTablet, isDesktop, isPortrait])

  // Memoize event handlers to prevent unnecessary re-renders
  const handleClickOutside = useCallback((event: MouseEvent) => {
    if (isMobile && isMobileMenuOpen) {
      const target = event.target as Element
      if (!target.closest('[data-sidebar]') && !target.closest('[data-mobile-menu-trigger]')) {
        setIsMobileMenuOpen(false)
      }
    }
  }, [isMobile, isMobileMenuOpen])

  const handleRouteChange = useCallback(() => {
    if (isMobile && isMobileMenuOpen) {
      setIsMobileMenuOpen(false)
    }
  }, [isMobile, isMobileMenuOpen])

  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    // Escape key closes mobile menu
    if (isMobile && event.key === 'Escape' && isMobileMenuOpen) {
      setIsMobileMenuOpen(false)
      return
    }

    // Ctrl/Cmd + B toggles sidebar (desktop only)
    if (!isMobile && (event.ctrlKey || event.metaKey) && event.key === 'b') {
      event.preventDefault()
      setIsCollapsed(!isCollapsed)
      return
    }

    // Ctrl/Cmd + M toggles mobile menu
    if (isMobile && (event.ctrlKey || event.metaKey) && event.key === 'm') {
      event.preventDefault()
      setIsMobileMenuOpen(!isMobileMenuOpen)
      return
    }
  }, [isMobile, isMobileMenuOpen, isCollapsed])

  // Close mobile menu when clicking outside or on route change
  useEffect(() => {
    document.addEventListener('mousedown', handleClickOutside)
    window.addEventListener('popstate', handleRouteChange)
    
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      window.removeEventListener('popstate', handleRouteChange)
    }
  }, [handleClickOutside, handleRouteChange])

  // Enhanced keyboard navigation support
  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown])

  const handleSidebarToggle = useCallback(() => {
    if (isMobile) {
      setIsMobileMenuOpen(!isMobileMenuOpen)
    } else {
      setIsCollapsed(!isCollapsed)
    }
  }, [isMobile, isMobileMenuOpen, isCollapsed])

  const handleMobileMenuToggle = useCallback(() => {
    setIsMobileMenuOpen(!isMobileMenuOpen)
  }, [isMobileMenuOpen])

  const handleOverlayClick = useCallback(() => {
    setIsMobileMenuOpen(false)
  }, [])

  const handleOverlayKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setIsMobileMenuOpen(false)
    }
  }, [])

  return (
    <div className={cn("relative", className)}>
      {/* Mobile Overlay with improved accessibility */}
      {isMobile && isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden backdrop-blur-sm"
          onClick={handleOverlayClick}
          onKeyDown={handleOverlayKeyDown}
          role="button"
          tabIndex={0}
          aria-label="Close navigation menu"
        />
      )}

      <AppShell
        sidebar={
          <div
            data-sidebar
            className={responsiveClasses.sidebar}
          >
            <AppSidebar 
              isCollapsed={!isMobile && isCollapsed}
              onCollapsedChange={handleSidebarToggle}
            />
          </div>
        }
        header={
          <AppHeader 
            onMobileMenuToggle={handleMobileMenuToggle}
            isMobile={isMobile}
          />
        }
      >
        {/* Main Content with Enhanced Responsive Padding */}
        <div className={responsiveClasses.mainContent}>
          <div className={responsiveClasses.container}>
            {children}
          </div>
        </div>
        
        {/* Enhanced Footer with better responsive behavior */}
        <footer className={responsiveClasses.footer}>
          <div className={responsiveClasses.footerContent}>
            <p>&copy; {currentYear} HHF Technology</p>
            <div className={responsiveClasses.footerLinks}>
              <p>Powered by CrowdSec (Only for Pangolin Users)</p>
              <p>CrowdSec Manager - Beta-version - v0.0.6</p>
            </div>
          </div>
        </footer>
      </AppShell>
    </div>
  )
})