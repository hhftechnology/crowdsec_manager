import { ReactNode, useState, useEffect } from 'react'
import Sidebar from './Sidebar'
import Header from './Header'
import { cn } from '@/lib/utils'
import { useMediaQuery } from '@/hooks/useMediaQuery'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const [isCollapsed, setIsCollapsed] = useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  
  // Responsive breakpoints
  const isMobile = useMediaQuery('(max-width: 768px)')
  const isTablet = useMediaQuery('(min-width: 769px) and (max-width: 1024px)')
  const isDesktop = useMediaQuery('(min-width: 1025px)')

  // Auto-collapse sidebar on mobile
  useEffect(() => {
    if (isMobile) {
      setIsCollapsed(true)
      setIsMobileMenuOpen(false)
    } else if (isTablet) {
      setIsCollapsed(true)
    } else if (isDesktop) {
      setIsCollapsed(false)
    }
  }, [isMobile, isTablet, isDesktop])

  // Close mobile menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (isMobile && isMobileMenuOpen) {
        const target = event.target as Element
        if (!target.closest('[data-sidebar]') && !target.closest('[data-mobile-menu-trigger]')) {
          setIsMobileMenuOpen(false)
        }
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [isMobile, isMobileMenuOpen])

  const handleSidebarToggle = () => {
    if (isMobile) {
      setIsMobileMenuOpen(!isMobileMenuOpen)
    } else {
      setIsCollapsed(!isCollapsed)
    }
  }

  return (
    <div className="flex h-full bg-background overflow-hidden">
      {/* Mobile Overlay */}
      {isMobile && isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
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
          // Responsive padding
          "p-3 sm:p-4 md:p-6",
          // Touch-friendly spacing on mobile
          isMobile && "pb-safe-area-inset-bottom"
        )}>
          <div className={cn(
            "mx-auto",
            // Responsive max-width
            "max-w-full",
            isTablet && "max-w-6xl",
            isDesktop && "max-w-7xl"
          )}>
            {children}
          </div>
        </main>
        
        {/* Footer - hidden on mobile to save space */}
        <footer className={cn(
          "border-t text-center text-xs text-muted-foreground bg-background transition-all",
          isMobile ? "hidden" : "p-4"
        )}>
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
            <p>&copy; {new Date().getFullYear()} HHF Technology</p>
            <div className="flex flex-col sm:flex-row gap-2 sm:gap-4">
              <p>Powered by CrowdSec (Only for Pangolin Users)</p>
              <p>CrowdSec Manager - Beta-version - v0.0.1</p>
            </div>
          </div>
        </footer>
      </div>
    </div>
  )
}
