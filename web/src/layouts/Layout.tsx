import { ReactNode, useState, useCallback } from 'react'
import Sidebar from './Sidebar'
import Header from './Header'
import { useConfigEvents } from '@/hooks/useConfigEvents'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  // Listen for config drift/missing events and show toast notifications
  useConfigEvents()
  const [isCollapsed, setIsCollapsed] = useState(
    () => localStorage.getItem('sidebar-collapsed') === 'true'
  )
  const [mobileOpen, setMobileOpen] = useState(false)

  const handleMobileNavigate = useCallback(() => {
    setMobileOpen(false)
  }, [])

  const handleToggleCollapse = useCallback(() => {
    setIsCollapsed((prev) => {
      const next = !prev
      localStorage.setItem('sidebar-collapsed', String(next))
      return next
    })
  }, [])

  return (
    <div className="h-full bg-background overflow-hidden">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Mobile sidebar drawer */}
      <div
        className={`fixed inset-y-0 left-0 z-50 md:hidden transition-transform duration-300 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <Sidebar
          isCollapsed={false}
          onNavigate={handleMobileNavigate}
        />
      </div>

      {/* Desktop layout */}
      <div className="flex h-full overflow-hidden">
        {/* Desktop sidebar */}
        <div className="hidden md:block shrink-0">
          <Sidebar isCollapsed={isCollapsed} />
        </div>

        <div className="flex flex-1 flex-col min-w-0 overflow-hidden">
          <Header
            onMenuClick={() => setMobileOpen(true)}
            isCollapsed={isCollapsed}
            onToggleCollapse={handleToggleCollapse}
          />
          <main className="flex-1 overflow-y-auto bg-background p-4 md:p-6">
            <div className="max-w-screen-2xl mx-auto w-full h-full">
              {children}
            </div>
          </main>
        </div>
      </div>
    </div>
  )
}
