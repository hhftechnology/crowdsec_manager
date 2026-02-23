import { useState, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Plus, Trash2 } from 'lucide-react'

interface BatchOperationsPanelProps {
  onBatchAdd: (ips: string[]) => void
  onBatchRemove: (ips: string[]) => void
  selectedCount: number
  className?: string
}

function parseIPs(raw: string): string[] {
  return raw
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

function BatchOperationsPanel({
  onBatchAdd,
  onBatchRemove,
  selectedCount,
  className,
}: BatchOperationsPanelProps) {
  const [inputValue, setInputValue] = useState('')

  const parsedIPs = parseIPs(inputValue)
  const count = parsedIPs.length

  const handleAdd = useCallback(() => {
    if (count > 0) {
      onBatchAdd(parsedIPs)
      setInputValue('')
    }
  }, [parsedIPs, count, onBatchAdd])

  const handleRemove = useCallback(() => {
    if (count > 0) {
      onBatchRemove(parsedIPs)
      setInputValue('')
    }
  }, [parsedIPs, count, onBatchRemove])

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center justify-between text-base">
          Bulk Operations
          {selectedCount > 0 && (
            <Badge variant="secondary">{selectedCount} selected</Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Textarea
            placeholder="Enter IP addresses or CIDR ranges, one per line..."
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            rows={6}
            className="font-mono text-sm"
          />
          {count > 0 && (
            <p className="text-xs text-muted-foreground">
              {count} address{count !== 1 ? 'es' : ''} detected
            </p>
          )}
        </div>

        <div className={cn('flex gap-2')}>
          <Button
            onClick={handleAdd}
            disabled={count === 0}
            className="flex-1 gap-2"
          >
            <Plus className="h-4 w-4" />
            Add
            {count > 0 && (
              <Badge variant="secondary" className="ml-1">
                {count}
              </Badge>
            )}
          </Button>
          <Button
            onClick={handleRemove}
            disabled={count === 0}
            variant="destructive"
            className="flex-1 gap-2"
          >
            <Trash2 className="h-4 w-4" />
            Remove
            {count > 0 && (
              <Badge variant="secondary" className="ml-1">
                {count}
              </Badge>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

export { BatchOperationsPanel }
export type { BatchOperationsPanelProps }
