import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { navigation } from '@/layouts/navigation'
import { Menu, Moon, Shield, Sun, X } from 'lucide-react'
import { useTheme } from '@/contexts/ThemeContext'

interface MobileNavigationProps {
  className?: string
}

function MobileNavigation({ className }: MobileNavigationProps) {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  const { theme, setTheme } = useTheme()

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }

  return (
    <div className={className}>
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setOpen(true)}
        aria-label="Open navigation menu"
      >
        <Menu className="h-5 w-5" />
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="inset-y-0 left-0 h-full w-72 translate-x-0 translate-y-0 rounded-none p-0 data-[state=closed]:slide-out-to-left data-[state=open]:slide-in-from-left sm:rounded-none [&>button]:hidden">
          <DialogTitle className="sr-only">Navigation Menu</DialogTitle>
          {/* Header */}
          <div className="flex items-center justify-between border-b p-4">
            <div className="flex items-center gap-2 font-semibold">
              <Shield className="h-5 w-5 text-primary" />
              <span>CrowdSec Manager</span>
            </div>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => setOpen(false)}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Navigation links */}
          <ScrollArea className="flex-1 px-2 py-4">
            <div className="space-y-6">
              {navigation.map((group) => (
                <div key={group.title}>
                  <h4 className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    {group.title}
                  </h4>
                  <div className="space-y-1">
                    {group.items.map((item) => {
                      const isActive = location.pathname === item.href
                      const Icon = item.icon
                      return (
                        <Link
                          key={item.name}
                          to={item.href}
                          onClick={() => setOpen(false)}
                          className={cn(
                            'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
                            isActive
                              ? 'bg-primary text-primary-foreground'
                              : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                          )}
                        >
                          <Icon className="h-4 w-4" />
                          {item.name}
                        </Link>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>

          {/* Footer with theme toggle */}
          <div className="border-t p-4">
            <Button
              variant="ghost"
              className="w-full justify-start"
              onClick={toggleTheme}
            >
              {theme === 'dark' ? (
                <Sun className="h-4 w-4" />
              ) : (
                <Moon className="h-4 w-4" />
              )}
              Toggle Theme
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export { MobileNavigation }
export type { MobileNavigationProps }
