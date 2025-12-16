import React, { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Keyboard, HelpCircle } from "lucide-react"
import { useAccessibility } from './AccessibilityProvider'
import { cn } from '@/lib/utils'

interface KeyboardShortcut {
  key: string
  ctrlKey?: boolean
  altKey?: boolean
  shiftKey?: boolean
  metaKey?: boolean
  description: string
  category?: string
}

interface KeyboardShortcutsDialogProps {
  trigger?: React.ReactNode
}

function formatShortcut(shortcut: KeyboardShortcut) {
  const keys = []
  
  if (shortcut.ctrlKey) keys.push('Ctrl')
  if (shortcut.altKey) keys.push('Alt')
  if (shortcut.shiftKey) keys.push('Shift')
  if (shortcut.metaKey) keys.push('Cmd')
  
  // Format special keys
  let keyDisplay = shortcut.key
  switch (shortcut.key.toLowerCase()) {
    case 'escape':
      keyDisplay = 'Esc'
      break
    case 'arrowup':
      keyDisplay = '↑'
      break
    case 'arrowdown':
      keyDisplay = '↓'
      break
    case 'arrowleft':
      keyDisplay = '←'
      break
    case 'arrowright':
      keyDisplay = '→'
      break
    case ' ':
      keyDisplay = 'Space'
      break
    default:
      keyDisplay = shortcut.key.toUpperCase()
  }
  
  keys.push(keyDisplay)
  
  return keys
}

function ShortcutBadge({ keys }: { keys: string[] }) {
  return (
    <div className="flex items-center gap-1">
      {keys.map((key, index) => (
        <React.Fragment key={index}>
          <Badge variant="outline" className="font-mono text-xs px-2 py-1">
            {key}
          </Badge>
          {index < keys.length - 1 && (
            <span className="text-muted-foreground text-xs">+</span>
          )}
        </React.Fragment>
      ))}
    </div>
  )
}

export function KeyboardShortcutsDialog({ trigger }: KeyboardShortcutsDialogProps) {
  const [open, setOpen] = useState(false)
  const { shortcuts } = useAccessibility()
  
  // Group shortcuts by category
  const groupedShortcuts = shortcuts.reduce((acc, shortcut) => {
    const category = shortcut.category || 'General'
    if (!acc[category]) {
      acc[category] = []
    }
    acc[category].push(shortcut)
    return acc
  }, {} as Record<string, KeyboardShortcut[]>)
  
  const categories = Object.keys(groupedShortcuts).sort()
  
  const defaultTrigger = (
    <Button
      variant="outline"
      size="sm"
      className="gap-2"
      data-help-trigger
    >
      <Keyboard className="h-4 w-4" />
      Keyboard Shortcuts
    </Button>
  )
  
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger || defaultTrigger}
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[80vh]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Keyboard className="h-5 w-5" />
            Keyboard Shortcuts
          </DialogTitle>
          <DialogDescription>
            Use these keyboard shortcuts to navigate the application more efficiently.
            Press <Badge variant="outline" className="mx-1 font-mono">?</Badge> to open this dialog anytime.
          </DialogDescription>
        </DialogHeader>
        
        <ScrollArea className="max-h-[60vh] pr-4">
          <div className="space-y-6">
            {categories.map((category) => (
              <div key={category}>
                <h3 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider mb-3">
                  {category}
                </h3>
                <div className="space-y-2">
                  {groupedShortcuts[category].map((shortcut, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between py-2 px-3 rounded-md hover:bg-muted/50 transition-colors"
                    >
                      <span className="text-sm">{shortcut.description}</span>
                      <ShortcutBadge keys={formatShortcut(shortcut)} />
                    </div>
                  ))}
                </div>
                {category !== categories[categories.length - 1] && (
                  <Separator className="mt-4" />
                )}
              </div>
            ))}
            
            {/* Additional accessibility shortcuts */}
            <div>
              <h3 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider mb-3">
                Accessibility
              </h3>
              <div className="space-y-2">
                <div className="flex items-center justify-between py-2 px-3 rounded-md hover:bg-muted/50 transition-colors">
                  <span className="text-sm">Navigate between interactive elements</span>
                  <ShortcutBadge keys={['Tab']} />
                </div>
                <div className="flex items-center justify-between py-2 px-3 rounded-md hover:bg-muted/50 transition-colors">
                  <span className="text-sm">Navigate backwards</span>
                  <ShortcutBadge keys={['Shift', 'Tab']} />
                </div>
                <div className="flex items-center justify-between py-2 px-3 rounded-md hover:bg-muted/50 transition-colors">
                  <span className="text-sm">Activate focused element</span>
                  <ShortcutBadge keys={['Enter']} />
                </div>
                <div className="flex items-center justify-between py-2 px-3 rounded-md hover:bg-muted/50 transition-colors">
                  <span className="text-sm">Activate button or toggle</span>
                  <ShortcutBadge keys={['Space']} />
                </div>
                <div className="flex items-center justify-between py-2 px-3 rounded-md hover:bg-muted/50 transition-colors">
                  <span className="text-sm">Navigate lists and menus</span>
                  <ShortcutBadge keys={['↑', '↓']} />
                </div>
              </div>
            </div>
          </div>
        </ScrollArea>
        
        <div className="flex items-center gap-2 pt-4 border-t">
          <HelpCircle className="h-4 w-4 text-muted-foreground" />
          <span className="text-xs text-muted-foreground">
            These shortcuts work when not typing in input fields. Some shortcuts may vary by browser.
          </span>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default KeyboardShortcutsDialog