import { useRef, useState, useCallback } from 'react'
import { useMountEffect } from '@/hooks/useMountEffect'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import type { LucideIcon } from 'lucide-react'

interface CommandEntry {
  label: string
  icon?: LucideIcon
  action: () => void
  group?: string
}

interface CommandPaletteProps {
  commands: CommandEntry[]
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

function CommandPalette({ commands, open: controlledOpen, onOpenChange }: CommandPaletteProps) {
  const [internalOpen, setInternalOpen] = useState(false)

  const isControlled = controlledOpen !== undefined
  const isOpen = isControlled ? controlledOpen : internalOpen

  const setOpen = useCallback(
    (value: boolean) => {
      if (isControlled) {
        onOpenChange?.(value)
      } else {
        setInternalOpen(value)
      }
    },
    [isControlled, onOpenChange]
  )

  const toggleRef = useRef<() => void>(() => {})
  toggleRef.current = () => setOpen(!isOpen)

  useMountEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        toggleRef.current()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  })

  // Group commands by their group field
  const grouped = commands.reduce<Record<string, CommandEntry[]>>((acc, cmd) => {
    const group = cmd.group ?? 'Actions'
    if (!acc[group]) {
      acc[group] = []
    }
    acc[group].push(cmd)
    return acc
  }, {})

  const handleSelect = useCallback(
    (command: CommandEntry) => {
      setOpen(false)
      command.action()
    },
    [setOpen]
  )

  return (
    <CommandDialog open={isOpen} onOpenChange={setOpen}>
      <CommandInput placeholder="Type a command or search..." />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>
        {Object.entries(grouped).map(([group, items]) => (
          <CommandGroup key={group} heading={group}>
            {items.map((command) => {
              const Icon = command.icon
              return (
                <CommandItem
                  key={command.label}
                  onSelect={() => handleSelect(command)}
                >
                  {Icon && <Icon className="mr-2 h-4 w-4" />}
                  <span>{command.label}</span>
                </CommandItem>
              )
            })}
          </CommandGroup>
        ))}
      </CommandList>
    </CommandDialog>
  )
}

export { CommandPalette }
export type { CommandPaletteProps, CommandEntry }
