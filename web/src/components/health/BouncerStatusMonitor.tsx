import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { EmptyState } from '@/components/common/ErrorStates'
import { Shield } from 'lucide-react'
import type { Bouncer } from '@/lib/api'
import { formatDate } from '@/lib/utils'

interface BouncerStatusMonitorProps {
  bouncers: Bouncer[]
  className?: string
}

function BouncerStatusMonitor({ bouncers, className }: BouncerStatusMonitorProps) {
  if (bouncers.length === 0) {
    return (
      <EmptyState
        icon={Shield}
        title="No bouncers found"
        description="No CrowdSec bouncers are currently registered."
        className={className}
      />
    )
  }

  return (
    <div className={cn('rounded-md border', className)}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>IP Address</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Version</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Last Pull</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {bouncers.map((bouncer) => (
            <TableRow key={bouncer.name}>
              <TableCell className="font-medium">{bouncer.name}</TableCell>
              <TableCell className="font-mono text-sm">{bouncer.ip_address}</TableCell>
              <TableCell>{bouncer.type || '-'}</TableCell>
              <TableCell>{bouncer.version || '-'}</TableCell>
              <TableCell>
                <Badge variant={bouncer.valid ? 'success' : 'destructive'}>
                  {bouncer.valid ? 'Valid' : 'Invalid'}
                </Badge>
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {bouncer.last_pull ? formatDate(bouncer.last_pull) : 'Never'}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

export { BouncerStatusMonitor }
export type { BouncerStatusMonitorProps }
