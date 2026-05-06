import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'

interface DurationFieldProps {
  value: string
  onChange: (value: string) => void
  id?: string
}

export function DurationField({ value, onChange, id = 'duration' }: DurationFieldProps) {
  const permanent = value === '0'

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <Label htmlFor={id}>Duration</Label>
        <div className="flex items-center gap-2">
          <Label htmlFor={`${id}-permanent`} className="text-sm font-normal text-muted-foreground">
            Permanent
          </Label>
          <Switch
            id={`${id}-permanent`}
            checked={permanent}
            onCheckedChange={(checked) => onChange(checked ? '0' : '4h')}
          />
        </div>
      </div>
      {!permanent && (
        <Input
          id={id}
          placeholder="4h"
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
      )}
    </div>
  )
}
