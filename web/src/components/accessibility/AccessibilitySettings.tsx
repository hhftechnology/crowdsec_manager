import React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { 
  Eye, 
  Zap, 
  Type, 
  Keyboard, 
  Volume2, 
  RotateCcw,
  Info,
  CheckCircle
} from 'lucide-react'
import { useAccessibility } from './AccessibilityProvider'
import { KeyboardShortcutsDialog } from './KeyboardShortcutsDialog'
import { cn } from '@/lib/utils'

interface AccessibilitySettingsProps {
  className?: string
}

export function AccessibilitySettings({ className }: AccessibilitySettingsProps) {
  const { settings, updateSetting, announceToScreenReader } = useAccessibility()
  
  const handleSettingChange = (key: keyof typeof settings, value: boolean) => {
    updateSetting(key, value)
    
    // Announce changes to screen readers
    const settingNames = {
      highContrast: 'High contrast mode',
      reducedMotion: 'Reduced motion',
      largeText: 'Large text',
      keyboardNavigation: 'Keyboard navigation',
      screenReaderOptimized: 'Screen reader optimization'
    }
    
    announceToScreenReader(
      `${settingNames[key]} ${value ? 'enabled' : 'disabled'}`,
      'polite'
    )
  }
  
  const resetToDefaults = () => {
    const defaults = {
      highContrast: false,
      reducedMotion: false,
      largeText: false,
      keyboardNavigation: true,
      screenReaderOptimized: false
    }
    
    Object.entries(defaults).forEach(([key, value]) => {
      updateSetting(key as keyof typeof settings, value)
    })
    
    announceToScreenReader('Accessibility settings reset to defaults', 'polite')
  }
  
  return (
    <Card className={cn("w-full", className)}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Eye className="h-5 w-5" />
          Accessibility Settings
        </CardTitle>
        <CardDescription>
          Customize the interface to meet your accessibility needs. Changes are saved automatically.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Visual Settings */}
        <div>
          <h3 className="font-semibold text-sm mb-4 flex items-center gap-2">
            <Eye className="h-4 w-4" />
            Visual
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Label htmlFor="high-contrast" className="text-sm font-medium">
                  High Contrast Mode
                </Label>
                <p className="text-xs text-muted-foreground">
                  Increases contrast for better visibility
                </p>
              </div>
              <Switch
                id="high-contrast"
                checked={settings.highContrast}
                onCheckedChange={(checked) => handleSettingChange('highContrast', checked)}
                aria-describedby="high-contrast-desc"
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Label htmlFor="large-text" className="text-sm font-medium">
                  Large Text
                </Label>
                <p className="text-xs text-muted-foreground">
                  Increases text size throughout the interface
                </p>
              </div>
              <Switch
                id="large-text"
                checked={settings.largeText}
                onCheckedChange={(checked) => handleSettingChange('largeText', checked)}
                aria-describedby="large-text-desc"
              />
            </div>
          </div>
        </div>
        
        <Separator />
        
        {/* Motion Settings */}
        <div>
          <h3 className="font-semibold text-sm mb-4 flex items-center gap-2">
            <Zap className="h-4 w-4" />
            Motion & Animation
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Label htmlFor="reduced-motion" className="text-sm font-medium">
                  Reduce Motion
                </Label>
                <p className="text-xs text-muted-foreground">
                  Minimizes animations and transitions
                </p>
              </div>
              <Switch
                id="reduced-motion"
                checked={settings.reducedMotion}
                onCheckedChange={(checked) => handleSettingChange('reducedMotion', checked)}
                aria-describedby="reduced-motion-desc"
              />
            </div>
          </div>
        </div>
        
        <Separator />
        
        {/* Navigation Settings */}
        <div>
          <h3 className="font-semibold text-sm mb-4 flex items-center gap-2">
            <Keyboard className="h-4 w-4" />
            Navigation
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Label htmlFor="keyboard-nav" className="text-sm font-medium">
                  Keyboard Navigation
                </Label>
                <p className="text-xs text-muted-foreground">
                  Enable keyboard shortcuts and navigation
                </p>
              </div>
              <Switch
                id="keyboard-nav"
                checked={settings.keyboardNavigation}
                onCheckedChange={(checked) => handleSettingChange('keyboardNavigation', checked)}
                aria-describedby="keyboard-nav-desc"
              />
            </div>
            
            {settings.keyboardNavigation && (
              <div className="ml-4 p-3 bg-muted/50 rounded-md">
                <div className="flex items-center justify-between">
                  <span className="text-sm">View keyboard shortcuts</span>
                  <KeyboardShortcutsDialog />
                </div>
              </div>
            )}
          </div>
        </div>
        
        <Separator />
        
        {/* Screen Reader Settings */}
        <div>
          <h3 className="font-semibold text-sm mb-4 flex items-center gap-2">
            <Volume2 className="h-4 w-4" />
            Screen Reader
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Label htmlFor="screen-reader" className="text-sm font-medium">
                  Screen Reader Optimization
                </Label>
                <p className="text-xs text-muted-foreground">
                  Optimizes interface for screen readers
                </p>
              </div>
              <Switch
                id="screen-reader"
                checked={settings.screenReaderOptimized}
                onCheckedChange={(checked) => handleSettingChange('screenReaderOptimized', checked)}
                aria-describedby="screen-reader-desc"
              />
            </div>
            
            {settings.screenReaderOptimized && (
              <div className="ml-4 p-3 bg-muted/50 rounded-md">
                <div className="flex items-center gap-2 text-sm text-green-700 dark:text-green-400">
                  <CheckCircle className="h-4 w-4" />
                  Screen reader optimizations active
                </div>
              </div>
            )}
          </div>
        </div>
        
        <Separator />
        
        {/* System Detection */}
        <div>
          <h3 className="font-semibold text-sm mb-4 flex items-center gap-2">
            <Info className="h-4 w-4" />
            System Preferences
          </h3>
          <div className="space-y-2 text-xs text-muted-foreground">
            <div className="flex items-center justify-between">
              <span>Prefers reduced motion:</span>
              <Badge variant={window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'default' : 'secondary'}>
                {window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'Yes' : 'No'}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span>Prefers high contrast:</span>
              <Badge variant={window.matchMedia('(prefers-contrast: high)').matches ? 'default' : 'secondary'}>
                {window.matchMedia('(prefers-contrast: high)').matches ? 'Yes' : 'No'}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span>Color scheme:</span>
              <Badge variant="secondary">
                {window.matchMedia('(prefers-color-scheme: dark)').matches ? 'Dark' : 'Light'}
              </Badge>
            </div>
          </div>
        </div>
        
        <Separator />
        
        {/* Reset Button */}
        <div className="flex justify-between items-center">
          <div>
            <p className="text-sm font-medium">Reset Settings</p>
            <p className="text-xs text-muted-foreground">
              Restore all accessibility settings to their defaults
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={resetToDefaults}
            className="gap-2"
          >
            <RotateCcw className="h-4 w-4" />
            Reset
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

export default AccessibilitySettings