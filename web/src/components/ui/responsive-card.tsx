import { HTMLAttributes, forwardRef } from "react"
import { cn } from "@/lib/utils"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "./card"
import { useBreakpoints } from "@/hooks/useMediaQuery"

interface ResponsiveCardProps extends HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'compact' | 'feature' | 'status'
  touchOptimized?: boolean
}

const ResponsiveCard = forwardRef<HTMLDivElement, ResponsiveCardProps>(
  ({ className, variant = 'default', touchOptimized = false, ...props }, ref) => {
    const { isMobile, isTablet } = useBreakpoints()
    
    return (
      <Card
        ref={ref}
        className={cn(
          "transition-all duration-200", 
          // Base responsive styles
          variant === 'default' && [
            "w-full", 
            isMobile && "rounded-lg shadow-sm", 
            isTablet && "rounded-xl shadow-md", 
            !isMobile && !isTablet && "rounded-xl shadow-lg hover:shadow-xl"
          ], 
          // Compact variant for mobile-first design
          variant === 'compact' && [
            "w-full", 
            isMobile && "p-3 rounded-md", 
            !isMobile && "p-4 rounded-lg"
          ], 
          // Feature cards with enhanced mobile experience
          variant === 'feature' && [
            "w-full cursor-pointer", 
            isMobile && "p-4 rounded-lg active:scale-95", 
            !isMobile && "p-6 rounded-xl hover:scale-105"
          ], 
          // Status cards with responsive indicators
          variant === 'status' && [
            "w-full border-l-4", 
            isMobile && "p-3 rounded-r-lg", 
            !isMobile && "p-4 rounded-r-xl"
          ], 
          // Touch optimization
          touchOptimized && [
            "touch-manipulation", 
            isMobile && "min-h-[60px] active:bg-accent/50"
          ], 
          className
        )}
        {...props}
      />
    )
  }
)
ResponsiveCard.displayName = "ResponsiveCard"

interface ResponsiveCardHeaderProps extends HTMLAttributes<HTMLDivElement> {
  compact?: boolean
}

const ResponsiveCardHeader = forwardRef<HTMLDivElement, ResponsiveCardHeaderProps>(
  ({ className, compact = false, ...props }, ref) => {
    const { isMobile } = useBreakpoints()
    
    return (
      <CardHeader
        ref={ref}
        className={cn(
          compact && isMobile ? "pb-2" : "pb-4", 
          isMobile && "px-4 pt-4", 
          className
        )}
        {...props}
      />
    )
  }
)
ResponsiveCardHeader.displayName = "ResponsiveCardHeader"

interface ResponsiveCardTitleProps extends HTMLAttributes<HTMLHeadingElement> {
  size?: 'sm' | 'md' | 'lg'
}

const ResponsiveCardTitle = forwardRef<HTMLParagraphElement, ResponsiveCardTitleProps>(
  ({ className, size = 'md', ...props }, ref) => {
    const { isMobile } = useBreakpoints()
    
    return (
      <CardTitle
        ref={ref}
        className={cn(
          // Responsive text sizing
          size === 'sm' && (isMobile ? "text-sm" : "text-base"), 
          size === 'md' && (isMobile ? "text-base" : "text-lg"), 
          size === 'lg' && (isMobile ? "text-lg" : "text-xl"), 
          // Mobile-specific adjustments
          isMobile && "leading-tight", 
          className
        )}
        {...props}
      />
    )
  }
)
ResponsiveCardTitle.displayName = "ResponsiveCardTitle"

interface ResponsiveCardContentProps extends HTMLAttributes<HTMLDivElement> {
  spacing?: 'tight' | 'normal' | 'loose'
}

const ResponsiveCardContent = forwardRef<HTMLDivElement, ResponsiveCardContentProps>(
  ({ className, spacing = 'normal', ...props }, ref) => {
    const { isMobile } = useBreakpoints()
    
    return (
      <CardContent
        ref={ref}
        className={cn(
          // Responsive spacing
          spacing === 'tight' && (isMobile ? "p-3" : "p-4"), 
          spacing === 'normal' && (isMobile ? "p-4" : "p-6"), 
          spacing === 'loose' && (isMobile ? "p-5" : "p-8"), 
          className
        )}
        {...props}
      />
    )
  }
)
ResponsiveCardContent.displayName = "ResponsiveCardContent"

interface ResponsiveCardFooterProps extends HTMLAttributes<HTMLDivElement> {
  sticky?: boolean
}

const ResponsiveCardFooter = forwardRef<HTMLDivElement, ResponsiveCardFooterProps>(
  ({ className, sticky = false, ...props }, ref) => {
    const { isMobile } = useBreakpoints()
    
    return (
      <CardFooter
        ref={ref}
        className={cn(
          // Responsive padding
          isMobile ? "px-4 pb-4 pt-2" : "px-6 pb-6 pt-4", 
          // Sticky footer for mobile
          sticky && isMobile && "sticky bottom-0 bg-card border-t", 
          className
        )}
        {...props}
      />
    )
  }
)
ResponsiveCardFooter.displayName = "ResponsiveCardFooter"

export {
  ResponsiveCard, 
  ResponsiveCardHeader, 
  ResponsiveCardTitle, 
  ResponsiveCardContent, 
  ResponsiveCardFooter, 
  ResponsiveCardDescription
}

// Re-export CardDescription as ResponsiveCardDescription for consistency
const ResponsiveCardDescription = CardDescription