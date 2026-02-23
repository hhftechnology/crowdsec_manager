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
          setIsCollapsed={setIsCollapsed}
          onNavigate={handleMobileNavigate}
        />
      </div>

      {/* Desktop layout */}
      <div className="grid grid-cols-1 md:grid-cols-[auto_1fr] h-full overflow-hidden">
        {/* Desktop sidebar */}
        <div className="hidden md:block">
          <Sidebar isCollapsed={isCollapsed} setIsCollapsed={setIsCollapsed} />
        </div>

        <div className="flex flex-col overflow-hidden">
          <Header onMenuClick={() => setMobileOpen(true)} />
          <main className="flex-1 overflow-y-auto bg-background p-4 md:p-6">
            <div className="max-w-[1600px] mx-auto w-full">
              {children}
            </div>
          </main>
          <footer className="border-t border-sidebar-border py-3 text-center text-xs text-muted-foreground bg-background">
            <p>&copy; {new Date().getFullYear()} HHF Technology &middot; Powered by CrowdSec</p>
          </footer>
        </div>
      </div>
    </div>
  )
}
