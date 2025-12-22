/**
 * Skip Links Component
 * Provides keyboard navigation shortcuts to main content areas
 */

import { DEFAULT_SKIP_LINKS, type SkipLink } from '@/lib/accessibility'
import { cn } from '@/lib/utils'

interface SkipLinksProps {
  links?: SkipLink[]
  className?: string
}

export function SkipLinks({ links = DEFAULT_SKIP_LINKS, className }: SkipLinksProps) {
  return (
    <nav 
      className={cn("skip-links", className)}
      aria-label="Skip navigation links"
    >
      {links.map((link, index) => (
        <a
          key={index}
          href={link.href}
          className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
        >
          {link.label}
        </a>
      ))}
    </nav>
  )
}

export default SkipLinks