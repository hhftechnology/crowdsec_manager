import * as React from "react"
import { cn } from "@/lib/utils"
import { useBreakpoints } from "@/hooks/useMediaQuery"

interface ResponsiveGridProps extends React.HTMLAttributes<HTMLDivElement> {
  cols?: {
    mobile?: number
    tablet?: number
    desktop?: number
    largeDesktop?: number
  }
  gap?: 'sm' | 'md' | 'lg' | 'xl'
  adaptive?: boolean
}

const ResponsiveGrid = React.forwardRef<HTMLDivElement, ResponsiveGridProps>(
  ({ 
    className, 
    cols = { mobile: 1, tablet: 2, desktop: 3, largeDesktop: 4 },
    gap = 'md',
    adaptive = true,
    ...props 
  }, ref) => {
    const { isMobile, isTablet, isDesktop, isLargeDesktop } = useBreakpoints()
    
    // Determine current columns based on screen size
    const getCurrentCols = () => {
      if (isMobile) return cols.mobile || 1
      if (isTablet) return cols.tablet || 2
      if (isLargeDesktop) return cols.largeDesktop || 4
      if (isDesktop) return cols.desktop || 3
      return cols.desktop || 3
    }
    
    const currentCols = getCurrentCols()
    
    return (
      <div
        ref={ref}
        className={cn(
          "grid w-full",
          // Responsive grid columns
          `grid-cols-${currentCols}`,
          // Responsive gaps
          gap === 'sm' && (isMobile ? "gap-2" : "gap-3"),
          gap === 'md' && (isMobile ? "gap-3" : "gap-4"),
          gap === 'lg' && (isMobile ? "gap-4" : "gap-6"),
          gap === 'xl' && (isMobile ? "gap-6" : "gap-8"),
          // Adaptive behavior
          adaptive && [
            "transition-all duration-300",
            isMobile && "auto-rows-min",
            !isMobile && "auto-rows-fr"
          ],
          className
        )}
        {...props}
      />
    )
  }
)
ResponsiveGrid.displayName = "ResponsiveGrid"

interface ResponsiveGridItemProps extends React.HTMLAttributes<HTMLDivElement> {
  span?: {
    mobile?: number
    tablet?: number
    desktop?: number
    largeDesktop?: number
  }
  order?: {
    mobile?: number
    tablet?: number
    desktop?: number
  }
}

const ResponsiveGridItem = React.forwardRef<HTMLDivElement, ResponsiveGridItemProps>(
  ({ 
    className, 
    span = {},
    order = {},
    ...props 
  }, ref) => {
    const { isMobile, isTablet, isDesktop, isLargeDesktop } = useBreakpoints()
    
    // Determine current span
    const getCurrentSpan = () => {
      if (isMobile && span.mobile) return span.mobile
      if (isTablet && span.tablet) return span.tablet
      if (isLargeDesktop && span.largeDesktop) return span.largeDesktop
      if (isDesktop && span.desktop) return span.desktop
      return 1
    }
    
    // Determine current order
    const getCurrentOrder = () => {
      if (isMobile && order.mobile) return order.mobile
      if (isTablet && order.tablet) return order.tablet
      if (isDesktop && order.desktop) return order.desktop
      return undefined
    }
    
    const currentSpan = getCurrentSpan()
    const currentOrder = getCurrentOrder()
    
    return (
      <div
        ref={ref}
        className={cn(
          // Column span
          currentSpan > 1 && `col-span-${currentSpan}`,
          // Order
          currentOrder && `order-${currentOrder}`,
          className
        )}
        {...props}
      />
    )
  }
)
ResponsiveGridItem.displayName = "ResponsiveGridItem"

interface ResponsiveFlexProps extends React.HTMLAttributes<HTMLDivElement> {
  direction?: {
    mobile?: 'row' | 'col'
    tablet?: 'row' | 'col'
    desktop?: 'row' | 'col'
  }
  align?: 'start' | 'center' | 'end' | 'stretch'
  justify?: 'start' | 'center' | 'end' | 'between' | 'around' | 'evenly'
  gap?: 'sm' | 'md' | 'lg' | 'xl'
  wrap?: boolean
}

const ResponsiveFlex = React.forwardRef<HTMLDivElement, ResponsiveFlexProps>(
  ({ 
    className, 
    direction = { mobile: 'col', tablet: 'row', desktop: 'row' },
    align = 'start',
    justify = 'start',
    gap = 'md',
    wrap = false,
    ...props 
  }, ref) => {
    const { isMobile, isTablet, isDesktop } = useBreakpoints()
    
    // Determine current direction
    const getCurrentDirection = () => {
      if (isMobile) return direction.mobile || 'col'
      if (isTablet) return direction.tablet || 'row'
      if (isDesktop) return direction.desktop || 'row'
      return 'row'
    }
    
    const currentDirection = getCurrentDirection()
    
    return (
      <div
        ref={ref}
        className={cn(
          "flex",
          // Direction
          currentDirection === 'col' ? "flex-col" : "flex-row",
          // Alignment
          align === 'start' && "items-start",
          align === 'center' && "items-center",
          align === 'end' && "items-end",
          align === 'stretch' && "items-stretch",
          // Justification
          justify === 'start' && "justify-start",
          justify === 'center' && "justify-center",
          justify === 'end' && "justify-end",
          justify === 'between' && "justify-between",
          justify === 'around' && "justify-around",
          justify === 'evenly' && "justify-evenly",
          // Gap
          gap === 'sm' && (isMobile ? "gap-2" : "gap-3"),
          gap === 'md' && (isMobile ? "gap-3" : "gap-4"),
          gap === 'lg' && (isMobile ? "gap-4" : "gap-6"),
          gap === 'xl' && (isMobile ? "gap-6" : "gap-8"),
          // Wrap
          wrap && "flex-wrap",
          className
        )}
        {...props}
      />
    )
  }
)
ResponsiveFlex.displayName = "ResponsiveFlex"

export {
  ResponsiveGrid,
  ResponsiveGridItem,
  ResponsiveFlex
}