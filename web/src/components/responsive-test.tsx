import React from 'react'
import { ResponsiveGrid, ResponsiveGridItem } from './ui/responsive-grid'
import { ResponsiveCard, ResponsiveCardContent, ResponsiveCardHeader, ResponsiveCardTitle } from './ui/responsive-card'
import { ResponsiveButton } from './ui/responsive-button'
import { useBreakpoints } from '@/hooks/useMediaQuery'

export function ResponsiveTest() {
  const { isMobile, isTablet, isDesktop } = useBreakpoints()
  
  return (
    <div className="p-4 space-y-6">
      <div className="text-center">
        <h1 className="text-2xl font-bold mb-2">Responsive Design Test</h1>
        <p className="text-muted-foreground">
          Current breakpoint: {isMobile ? 'Mobile' : isTablet ? 'Tablet' : isDesktop ? 'Desktop' : 'Unknown'}
        </p>
      </div>
      
      <ResponsiveGrid
        cols={{
          mobile: 1,
          tablet: 2,
          desktop: 3
        }}
        gap="md"
      >
        <ResponsiveGridItem>
          <ResponsiveCard variant="feature" touchOptimized>
            <ResponsiveCardHeader>
              <ResponsiveCardTitle>Card 1</ResponsiveCardTitle>
            </ResponsiveCardHeader>
            <ResponsiveCardContent>
              <p>This is a responsive card that adapts to different screen sizes.</p>
              <ResponsiveButton fullWidth className="mt-4">
                Action Button
              </ResponsiveButton>
            </ResponsiveCardContent>
          </ResponsiveCard>
        </ResponsiveGridItem>
        
        <ResponsiveGridItem>
          <ResponsiveCard variant="status">
            <ResponsiveCardHeader>
              <ResponsiveCardTitle>Card 2</ResponsiveCardTitle>
            </ResponsiveCardHeader>
            <ResponsiveCardContent>
              <p>Another responsive card with status styling.</p>
            </ResponsiveCardContent>
          </ResponsiveCard>
        </ResponsiveGridItem>
        
        <ResponsiveGridItem>
          <ResponsiveCard variant="compact">
            <ResponsiveCardHeader compact>
              <ResponsiveCardTitle size="sm">Card 3</ResponsiveCardTitle>
            </ResponsiveCardHeader>
            <ResponsiveCardContent spacing="tight">
              <p>Compact card for mobile optimization.</p>
            </ResponsiveCardContent>
          </ResponsiveCard>
        </ResponsiveGridItem>
      </ResponsiveGrid>
    </div>
  )
}