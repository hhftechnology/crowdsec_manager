import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { useLocation } from "react-router-dom"
import { Avatar } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { User, Settings, Github, Book, Menu, Shield } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import EnrollDialog from "@/components/EnrollDialog"
import { CrowdSecLogo } from "@/components/icons/CrowdSecLogo"
import { cn } from "@/lib/utils"

interface HeaderProps {
  onMobileMenuToggle?: () => void
  isMobile?: boolean
  isMobileMenuOpen?: boolean
}

export default function Header({ 
  onMobileMenuToggle, 
  isMobile = false, 
  isMobileMenuOpen = false 
}: HeaderProps) {
  const location = useLocation()
  
  // Generate breadcrumbs from path
  const pathSegments = location.pathname.split('/').filter(Boolean)
  const breadcrumbs = [
    { name: 'Home', href: '/' },
    ...pathSegments.map((segment, index) => {
      const href = `/${pathSegments.slice(0, index + 1).join('/')}`
      return {
        name: segment.charAt(0).toUpperCase() + segment.slice(1).replace(/-/g, ' '),
        href
      }
    })
  ]

  return (
    <header className={cn(
      "border-b border-border bg-background flex items-center justify-between transition-all",
      // Responsive height and padding
      isMobile ? "h-14 px-4" : "h-16 px-6"
    )}>
      {/* Left Section: Mobile Menu + Breadcrumbs */}
      <div className="flex items-center gap-3 min-w-0 flex-1">
        {/* Mobile Menu Toggle */}
        {isMobile && (
          <div className="flex items-center gap-3">
            <Button
              variant="ghost"
              size="icon"
              onClick={onMobileMenuToggle}
              data-mobile-menu-trigger
              className="h-9 w-9"
            >
              <Menu className="h-5 w-5" />
            </Button>
            
            {/* Mobile Logo */}
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              <div className="flex flex-col">
                <span className="text-sm font-semibold">CrowdSec</span>
                <Badge variant="secondary" className="text-[8px] px-1 py-0 h-3 w-fit">
                  Beta
                </Badge>
              </div>
            </div>
          </div>
        )}

        {/* Breadcrumbs - Hidden on small mobile screens */}
        <div className={cn(
          "flex items-center min-w-0",
          isMobile && "hidden sm:flex"
        )}>
          <Breadcrumb>
            <BreadcrumbList>
              {breadcrumbs.map((item, index) => (
                <div key={item.href} className="flex items-center">
                  <BreadcrumbItem>
                    {index === breadcrumbs.length - 1 ? (
                      <BreadcrumbPage className={cn(
                        "truncate",
                        isMobile && "max-w-[120px]"
                      )}>
                        {item.name}
                      </BreadcrumbPage>
                    ) : (
                      <BreadcrumbLink 
                        href={item.href}
                        className={cn(
                          "truncate",
                          isMobile && "max-w-[80px]"
                        )}
                      >
                        {item.name}
                      </BreadcrumbLink>
                    )}
                  </BreadcrumbItem>
                  {index < breadcrumbs.length - 1 && (
                    <BreadcrumbSeparator />
                  )}
                </div>
              ))}
            </BreadcrumbList>
          </Breadcrumb>
        </div>
      </div>

      {/* Right Section: Links & User Profile */}
      <div className="flex items-center gap-2 sm:gap-4">
        {/* Social Links - Hidden on mobile, shown on tablet+ */}
        <div className={cn(
          "items-center gap-2 mr-2",
          isMobile ? "hidden" : "flex"
        )}>
          <Button variant="outline" asChild className="gap-2">
            <a
              href="https://github.com/hhftechnology/crowdsec_manager"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Github className="h-4 w-4" />
              <span className="hidden lg:inline">GitHub</span>
            </a>
          </Button>
          <Button variant="outline" asChild className="gap-2">
            <a
              href="https://discord.gg/PEGcTJPfJ2"
              target="_blank"
              rel="noopener noreferrer"
            >
              {/* Discord Icon SVG */}
              <svg
                role="img"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
                className="h-4 w-4 fill-current"
              >
                <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.579.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.077.077 0 0 0 .084-.027c.461-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.068 0a.074.074 0 0 1 .078.01c.118.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.076.076 0 0 0-.04.106c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.418 2.157-2.418 1.21 0 2.176 1.096 2.157 2.419 0 1.334-.956 2.419-2.157 2.419zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.418 2.157-2.418 1.21 0 2.176 1.096 2.157 2.419 0 1.334-.956 2.419-2.157 2.419z" />
              </svg>
              <span className="hidden lg:inline">Discord</span>
            </a>
          </Button>
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Avatar className={cn(
              "cursor-pointer hover:opacity-80 transition-opacity bg-transparent",
              isMobile ? "h-7 w-7" : "h-8 w-8"
            )}>
              <CrowdSecLogo className="h-full w-full text-primary p-1" />
            </Avatar>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>CrowdSec</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <EnrollDialog 
              trigger={
                <DropdownMenuItem onSelect={(e) => e.preventDefault()} className="cursor-pointer">
                  <Settings className="mr-2 h-4 w-4" />
                  <span>Enroll CrowdSec</span>
                </DropdownMenuItem>
              }
            />
            <DropdownMenuItem asChild>
              <a href="https://app.crowdsec.net/" target="_blank" rel="noopener noreferrer" className="cursor-pointer">
                <User className="mr-2 h-4 w-4" />
                <span>Get your enroll key</span>
              </a>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <a href="https://docs.crowdsec.net/" target="_blank" rel="noopener noreferrer" className="cursor-pointer">
                <Book className="mr-2 h-4 w-4" />
                <span>CrowdSec Documentation</span>
              </a>
            </DropdownMenuItem>
            
            {/* Mobile-only social links */}
            {isMobile && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <a href="https://github.com/hhftechnology/crowdsec_manager" target="_blank" rel="noopener noreferrer" className="cursor-pointer">
                    <Github className="mr-2 h-4 w-4" />
                    <span>GitHub</span>
                  </a>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a href="https://discord.gg/PEGcTJPfJ2" target="_blank" rel="noopener noreferrer" className="cursor-pointer">
                    <svg
                      role="img"
                      viewBox="0 0 24 24"
                      xmlns="http://www.w3.org/2000/svg"
                      className="mr-2 h-4 w-4 fill-current"
                    >
                      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.579.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.077.077 0 0 0 .084-.027c.461-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.068 0a.074.074 0 0 1 .078.01c.118.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.076.076 0 0 0-.04.106c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.418 2.157-2.418 1.21 0 2.176 1.096 2.157 2.419 0 1.334-.956 2.419-2.157 2.419zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.418 2.157-2.418 1.21 0 2.176 1.096 2.157 2.419 0 1.334-.956 2.419-2.157 2.419z" />
                    </svg>
                    <span>Discord</span>
                  </a>
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
