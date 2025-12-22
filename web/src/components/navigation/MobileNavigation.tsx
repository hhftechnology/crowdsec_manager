import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  Shield,
  Menu,
  X,
  ChevronDown,
  ChevronRight,
  Home,
  Search
} from 'lucide-react'
import { Input } from '@/components/ui/input'

interface NavigationItem {
  name: string
  href: string
  icon: any
  badge?: string | number
  children?: NavigationItem[]
}

interface NavigationGroup {
  title: string
  items: NavigationItem[]
}

interface MobileNavigationProps {
  navigation: NavigationGroup[]
  className?: string
}

export function MobileNavigation({ navigation, className }: MobileNavigationProps) {
  const { isMobile, needsTouchOptimization } = useBreakpoints()
  const location = useLocation()
  const [isOpen, setIsOpen] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())

  // Filter navigation items based on search
  const filteredNavigation = React.useMemo(() => {
    if (!searchTerm) return navigation

    return navigation.map(group => ({
      ...group,
      items: group.items.filter(item =>
        item.name.toLowerCase().includes(searchTerm.toLowerCase())
      )
    })).filter(group => group.items.length > 0)
  }, [navigation, searchTerm])

  const toggleGroup = (groupTitle: string) => {
    const newExpanded = new Set(expandedGroups)
    if (newExpanded.has(groupTitle)) {
      newExpanded.delete(groupTitle)
    } else {
      newExpanded.add(groupTitle)
    }
    setExpandedGroups(newExpanded)
  }

  const handleItemClick = () => {
    setIsOpen(false)
    setSearchTerm('')
  }

  if (!isMobile) {
    return null
  }

  return (
    <Sheet open={isOpen} onOpenChange={setIsOpen}>
      <SheetTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={cn(
            "h-9 w-9",
            needsTouchOptimization && "min-h-[44px] min-w-[44px]"
          )}
          data-mobile-menu-trigger
        >
          <Menu className="h-5 w-5" />
          <span className="sr-only">Open navigation menu</span>
        </Button>
      </SheetTrigger>
      
      <SheetContent 
        side="left" 
        className="p-0 w-80 max-w-[85vw]"
        onInteractOutside={() => setIsOpen(false)}
      >
        <div className="flex flex-col h-full bg-card text-card-foreground">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b">
            <div className="flex items-center gap-2 font-semibold text-lg">
              <Shield className="h-6 w-6 text-primary" />
              <div className="flex flex-col">
                <span>CrowdSec Manager</span>
                <Badge variant="outline" className="text-xs w-fit mt-1">
                  Mobile
                </Badge>
              </div>
            </div>
            
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setIsOpen(false)}
              className="h-8 w-8"
            >
              <X className="h-4 w-4" />
              <span className="sr-only">Close navigation</span>
            </Button>
          </div>

          {/* Search */}
          <div className="p-4 border-b">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search navigation..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9 min-h-[44px]"
                data-search-input
              />
            </div>
          </div>

          {/* Quick Actions */}
          <div className="p-4 border-b">
            <div className="grid grid-cols-2 gap-2">
              <Button
                variant="outline"
                size="sm"
                asChild
                className="justify-start min-h-[44px]"
                onClick={handleItemClick}
              >
                <Link to="/">
                  <Home className="h-4 w-4 mr-2" />
                  Dashboard
                </Link>
              </Button>
              <Button
                variant="outline"
                size="sm"
                asChild
                className="justify-start min-h-[44px]"
                onClick={handleItemClick}
              >
                <Link to="/health">
                  <Shield className="h-4 w-4 mr-2" />
                  Health
                </Link>
              </Button>
            </div>
          </div>

          {/* Navigation */}
          <ScrollArea className="flex-1 px-2 py-4">
            <div className="space-y-4">
              {filteredNavigation.map((group) => {
                const isExpanded = expandedGroups.has(group.title)
                const hasActiveItem = group.items.some(item => location.pathname === item.href)

                return (
                  <Collapsible
                    key={group.title}
                    open={isExpanded || hasActiveItem}
                    onOpenChange={() => toggleGroup(group.title)}
                  >
                    <CollapsibleTrigger asChild>
                      <Button
                        variant="ghost"
                        className="w-full justify-between p-2 h-auto min-h-[44px]"
                      >
                        <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                          {group.title}
                        </span>
                        {isExpanded || hasActiveItem ? (
                          <ChevronDown className="h-4 w-4" />
                        ) : (
                          <ChevronRight className="h-4 w-4" />
                        )}
                      </Button>
                    </CollapsibleTrigger>
                    
                    <CollapsibleContent className="space-y-1 mt-2">
                      {group.items.map((item) => {
                        const isActive = location.pathname === item.href
                        const Icon = item.icon
                        
                        return (
                          <Link
                            key={item.name}
                            to={item.href}
                            onClick={handleItemClick}
                            className={cn(
                              "flex items-center gap-3 rounded-md text-sm transition-colors px-4 py-3 min-h-[48px]",
                              isActive
                                ? "bg-primary text-primary-foreground"
                                : "text-muted-foreground hover:bg-accent hover:text-accent-foreground active:bg-accent/80"
                            )}
                          >
                            <Icon className="h-5 w-5 flex-shrink-0" />
                            <span className="flex-1 truncate">{item.name}</span>
                            {item.badge && (
                              <Badge 
                                variant={isActive ? "secondary" : "outline"} 
                                className="text-xs"
                              >
                                {item.badge}
                              </Badge>
                            )}
                          </Link>
                        )
                      })}
                    </CollapsibleContent>
                  </Collapsible>
                )
              })}
            </div>
          </ScrollArea>

          {/* Footer */}
          <div className="p-4 border-t">
            <div className="text-xs text-muted-foreground text-center">
              <p>&copy; {new Date().getFullYear()} HHF Technology</p>
              <p className="mt-1">CrowdSec Manager v0.0.1</p>
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  )
}

export default MobileNavigation