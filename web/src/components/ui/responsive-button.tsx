import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"
import { useBreakpoints } from "@/hooks/useMediaQuery"

const responsiveButtonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/90",
        destructive: "bg-destructive text-destructive-foreground hover:bg-destructive/90",
        outline: "border border-input bg-background hover:bg-accent hover:text-accent-foreground",
        secondary: "bg-secondary text-secondary-foreground hover:bg-secondary/80",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-9 rounded-md px-3",
        lg: "h-11 rounded-md px-8",
        icon: "h-10 w-10",
        // Touch-friendly sizes
        touch: "h-12 px-6 py-3",
        "touch-sm": "h-10 px-4 py-2",
        "touch-lg": "h-14 px-8 py-4",
      },
      responsive: {
        true: "",
        false: "",
      },
      touchOptimized: {
        true: "touch-manipulation active:scale-95 select-none",
        false: "",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
      responsive: true,
      touchOptimized: false,
    },
  }
)

export interface ResponsiveButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof responsiveButtonVariants> {
  asChild?: boolean
  fullWidth?: boolean
  loading?: boolean
  loadingText?: string
}

const ResponsiveButton = React.forwardRef<HTMLButtonElement, ResponsiveButtonProps>(
  ({ 
    className, 
    variant, 
    size, 
    responsive = true,
    touchOptimized,
    asChild = false, 
    fullWidth = false,
    loading = false,
    loadingText,
    children,
    disabled,
    ...props 
  }, ref) => {
    const { isMobile, isTouchDevice } = useBreakpoints()
    const Comp = asChild ? Slot : "button"
    
    // Auto-enable touch optimization on touch devices
    const shouldOptimizeForTouch = touchOptimized || (responsive && isTouchDevice)
    
    // Adjust size for mobile if responsive
    const getResponsiveSize = () => {
      if (!responsive) return size
      
      if (isMobile) {
        switch (size) {
          case 'sm': return shouldOptimizeForTouch ? 'touch-sm' : 'sm'
          case 'lg': return shouldOptimizeForTouch ? 'touch-lg' : 'lg'
          case 'icon': return shouldOptimizeForTouch ? 'touch' : 'icon'
          default: return shouldOptimizeForTouch ? 'touch' : 'default'
        }
      }
      
      return size
    }
    
    const responsiveSize = getResponsiveSize()
    
    return (
      <Comp
        className={cn(
          responsiveButtonVariants({ 
            variant, 
            size: responsiveSize, 
            responsive, 
            touchOptimized: shouldOptimizeForTouch 
          }),
          // Full width
          fullWidth && "w-full",
          // Mobile-specific adjustments
          responsive && isMobile && [
            "text-base", // Larger text on mobile
            "min-h-[44px]", // Minimum touch target size
          ],
          // Loading state
          loading && "cursor-not-allowed opacity-70",
          className
        )}
        ref={ref}
        disabled={disabled || loading}
        {...props}
      >
        {loading && (
          <svg
            className="mr-2 h-4 w-4 animate-spin"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="m4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}
        {loading ? (loadingText || "Loading...") : children}
      </Comp>
    )
  }
)
ResponsiveButton.displayName = "ResponsiveButton"

export { ResponsiveButton, responsiveButtonVariants }