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
 * responsive behavior and mobile optimizations using CSS Grid
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
      "grid h-screen bg-background overflow-hidden",
      // CSS Grid layout for proper alignment
      sidebar && header 
        ? "grid-cols-[auto_1fr] grid-rows-[auto_1fr]"
        : sidebar 
        ? "grid-cols-[auto_1fr] grid-rows-[1fr]"
        : header
        ? "grid-cols-[1fr] grid-rows-[auto_1fr]"
        : "grid-cols-[1fr] grid-rows-[1fr]",
      // Add safe area padding for mobile devices with notches
      isMobile && "min-h-screen-safe",
      // Ensure proper touch scrolling behavior on mobile
      needsTouchOptimization && "overscroll-behavior-contain",
      className
    )}
    style={{
      gridTemplateAreas: sidebar && header 
        ? '"sidebar header" "sidebar main"'
        : sidebar 
        ? '"sidebar main"'
        : header
        ? '"header" "main"'
        : '"main"'
    }}
  >
    {/* Sidebar */}
    {sidebar && (
      <aside 
        className="flex-shrink-0" 
        role="complementary" 
        aria-label="Navigation sidebar"
        style={{ gridArea: 'sidebar' }}
      >
        {sidebar}
      </aside>
    )}
    
    {/* Header */}
    {header && (
      <header 
        className="flex-shrink-0" 
        role="banner"
        style={{ gridArea: 'header' }}
      >
        {header}
      </header>
    )}
    
    {/* Main Content */}
    <main 
      className={cn(
        "overflow-y-auto overflow-x-hidden",
        // Optimize scrolling for mobile devices
        isMobile && "overscroll-behavior-y-contain",
        // Add safe area padding for devices with bottom home indicators
        isMobile && "pb-safe-area-inset-bottom"
      )}
      role="main"
      aria-label="Main content"
      style={{ gridArea: 'main' }}
    >
      {children}
    </main>
  </div>
  )
}