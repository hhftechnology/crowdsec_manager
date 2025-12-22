/**
 * @deprecated This component is deprecated. Use ResponsiveLayout from './layout/ResponsiveLayout' instead.
 * This file will be removed in a future version.
 */

import { ReactNode, useState, useEffect } from 'react'
import Sidebar from './Sidebar'
import Header from './Header'
import { cn } from '@/lib/utils'
import { useBreakpoints } from '@/hooks/useMediaQuery'

interface LayoutProps {
  children: ReactNode
}

/**
 * @deprecated Use ResponsiveLayout from './layout/ResponsiveLayout' instead
 */
export default function Layout({ children }: LayoutProps) {
  const [isCollapsed, setIsCollapsed] = useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  
  // Enhanced responsive breakpoints
  const { 
    isMobile, 
    isTablet, 
    isDesktop, 
    // needsTouchOptimization, // Unused in deprecated component
    // isLandscape, // Unused in deprecated component
    isPortrait 
  } = useBreakpoints()

  // Auto-collapse sidebar based on screen size and orientation
  useEffect(() => {
    if (isMobile) {
      setIsCollapsed(true)
      setIsMobileMenuOpen(false)
    } else if (isTablet) {
      // On tablet, consider orientation
      setIsCollapsed(isPortrait ? true : false)
    } else if (isDesktop) {
      setIsCollapsed(false)
    }
  }, [isMobile, isTablet, isDesktop, isPortrait])

  // Close mobile menu when clicking outside or on route change
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (isMobile && isMobileMenuOpen) {
        const target = event.target as Element
        if (!target.closest('[data-sidebar]') && !target.closest('[data-mobile-menu-trigger]')) {
          setIsMobileMenuOpen(false)
        }
      }
    }

    const handleRouteChange = () => {
      if (isMobile && isMobileMenuOpen) {
        setIsMobileMenuOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    window.addEventListener('popstate', handleRouteChange)
    
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      window.removeEventListener('popstate', handleRouteChange)
    }
  }, [isMobile, isMobileMenuOpen])

  // Handle keyboard navigation for mobile menu
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (isMobile && event.key === 'Escape' && isMobileMenuOpen) {
        setIsMobileMenuOpen(false)
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [isMobile, isMobileMenuOpen])

  const handleSidebarToggle = () => {
    if (isMobile) {
      setIsMobileMenuOpen(!isMobileMenuOpen)
    } else {
      setIsCollapsed(!isCollapsed)
    }
  }

  return (
    <div className={cn(
      "flex h-full bg-background overflow-hidden",
      // Add safe area padding for mobile devices
      isMobile && "min-h-screen-safe"
    )}>
      {/* Mobile Overlay */}
      {isMobile && isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden backdrop-blur-sm"
          onClick={() => setIsMobileMenuOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <div
        data-sidebar
        className={cn(
          "transition-all duration-300 ease-in-out z-50",
          // Mobile: slide in from left as overlay
          isMobile && [
            "fixed inset-y-0 left-0",
            isMobileMenuOpen ? "translate-x-0" : "-translate-x-full"
          ],
          // Tablet/Desktop: normal sidebar behavior
          !isMobile && "relative"
        )}
      >
        <Sidebar 
          isCollapsed={!isMobile && isCollapsed} 
          setIsCollapsed={handleSidebarToggle}
          isMobile={isMobile}
          isMobileMenuOpen={isMobileMenuOpen}
        />
      </div>

      {/* Main Content */}
      <div className="flex flex-col flex-1 overflow-hidden min-w-0">
        <Header 
          onMobileMenuToggle={handleSidebarToggle}
          isMobile={isMobile}
          isMobileMenuOpen={isMobileMenuOpen}
        />
        
        <main className={cn(
          "flex-1 overflow-y-auto bg-background transition-all duration-300",
          // Responsive padding with touch-friendly spacing
          isMobile ? "p-3 pb-safe-bottom" : isTablet ? "p-4" : "p-6",
          // Ensure proper scrolling on mobile
          isMobile && "overscroll-behavior-y-contain"
        )}>
          <div className={cn(
            "mx-auto w-full",
            // Responsive max-width
            isMobile ? "max-w-full" : isTablet ? "max-w-6xl" : "max-w-7xl"
          )}>
            {children}
          </div>
        </main>
        
        {/* Footer - adaptive visibility */}
        <footer className={cn(
          "border-t text-center text-xs text-muted-foreground bg-background transition-all",
          // Hide on mobile portrait, show on landscape and larger screens
          isMobile && isPortrait ? "hidden" : "p-4",
          // Add safe area padding on mobile
          isMobile && "pb-safe-bottom"
        )}>
          <div className={cn(
            "flex gap-2",
            isMobile ? "flex-col items-center" : "flex-row justify-between items-center"
          )}>
            <p>&copy; {new Date().getFullYear()} HHF Technology</p>
            <div className={cn(
              "flex gap-2",
              isMobile ? "flex-col items-center" : "flex-row gap-4"
            )}>
              <p>Powered by CrowdSec (Only for Pangolin Users)</p>
              <p>CrowdSec Manager - Beta-version - v0.0.1</p>
            </div>
          </div>
        </footer>
      </div>
    </div>
  )
}
