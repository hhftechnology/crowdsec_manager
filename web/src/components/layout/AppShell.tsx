import { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { useBreakpoints } from '@/hooks/useMediaQuery'

interface AppShellProps {
  children: ReactNode
  sidebar?: ReactNode
  header?: ReactNode
  className?: string
}

/**
 * AppShell - Main layout wrapper component
 * Provides the foundational structure for the application layout
 * following the shadcn-admin template architecture with enhanced
 * responsive behavior and mobile optimizations
 */
export function AppShell({ 
  children, 
  sidebar, 
  header, 
  className 
}: AppShellProps) {
  const { isMobile, needsTouchOptimization } = useBreakpoints()

  return (
    <div className={cn(
      "flex h-screen bg-background overflow-hidden",
      // Add safe area padding for mobile devices with notches
      isMobile && "min-h-screen-safe",
      // Ensure proper touch scrolling behavior on mobile
      needsTouchOptimization && "overscroll-behavior-contain",
      className
    )}>
      {/* Sidebar */}
      {sidebar && (
        <aside className="flex-shrink-0" role="complementary" aria-label="Navigation sidebar">
          {sidebar}
        </aside>
      )}
      
      {/* Main Content Area */}
      <div className="flex flex-col flex-1 overflow-hidden min-w-0">
        {/* Header */}
        {header && (
          <header className="flex-shrink-0" role="banner">
            {header}
          </header>
        )}
        
        {/* Main Content */}
        <main 
          className={cn(
            "flex-1 overflow-y-auto",
            // Optimize scrolling for mobile devices
            isMobile && "overscroll-behavior-y-contain",
            // Add safe area padding for devices with bottom home indicators
            isMobile && "pb-safe-area-inset-bottom"
          )}
          role="main"
          aria-label="Main content"
        >
          {children}
        </main>
      </div>
    </div>
  )
}