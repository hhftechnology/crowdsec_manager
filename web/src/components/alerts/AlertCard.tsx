import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import type { CrowdSecAlert, Decision } from '@/lib/api'
import { crowdsecAPI } from '@/lib/api/crowdsec'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { AlertTriangle, Info, Eye } from 'lucide-react'

interface AlertCardProps {
  alert: CrowdSecAlert
  index: number
  isExpanded: boolean
  onToggle: () => void
}

function AlertCard({ alert, isExpanded, onToggle }: AlertCardProps) {
  const [inspectOpen, setInspectOpen] = useState(false)

  return (
    <>
    <Collapsible open={isExpanded} onOpenChange={onToggle}>
      <Card className="border-l-4 border-l-orange-500">
        <CollapsibleTrigger className="w-full">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-orange-500" />
                <div className="text-left">
                  <CardTitle className="text-base">{alert.scenario}</CardTitle>
                  <CardDescription className="text-sm">
                    {alert.scope}: {alert.value}
                  </CardDescription>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={alert.type === 'ban' ? 'destructive' : 'default'}>
                  {alert.type || 'Unknown'}
                </Badge>
                <Badge variant="secondary">{alert.origin}</Badge>
                <Info className="h-4 w-4 text-muted-foreground" />
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent>
            <div className="grid gap-3 md:grid-cols-2 text-sm">
              <div>
                <span className="font-medium">Alert ID:</span>{' '}
                <span className="text-muted-foreground">{alert.id}</span>
              </div>
              <div>
                <span className="font-medium">Events Count:</span>{' '}
                <span className="text-muted-foreground">{alert.events_count || 0}</span>
              </div>
              <div>
                <span className="font-medium">Start Time:</span>{' '}
                <span className="text-muted-foreground">
                  {new Date(alert.start_at).toLocaleString()}
                </span>
              </div>
              <div>
                <span className="font-medium">Stop Time:</span>{' '}
                <span className="text-muted-foreground">
                  {alert.stop_at ? new Date(alert.stop_at).toLocaleString() : 'Ongoing'}
                </span>
              </div>
              {alert.capacity && (
                <div>
                  <span className="font-medium">Capacity:</span>{' '}
                  <span className="text-muted-foreground">{alert.capacity}</span>
                </div>
              )}
              {alert.leakspeed && (
                <div>
                  <span className="font-medium">Leak Speed:</span>{' '}
                  <span className="text-muted-foreground">{alert.leakspeed}</span>
                </div>
              )}
              {alert.simulated !== undefined && (
                <div>
                  <span className="font-medium">Simulated:</span>{' '}
                  <Badge variant={alert.simulated ? 'outline' : 'default'}>
                    {alert.simulated ? 'Yes' : 'No'}
                  </Badge>
                </div>
              )}
              {alert.message && (
                <div className="col-span-2">
                  <span className="font-medium">Message:</span>{' '}
                  <span className="text-muted-foreground">{alert.message}</span>
                </div>
              )}
            </div>
            {alert.decisions && alert.decisions.length > 0 && (
              <div className="mt-4">
                <h4 className="font-medium mb-2">Associated Decisions</h4>
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Type</TableHead>
                        <TableHead>Value</TableHead>
                        <TableHead>Duration</TableHead>
                        <TableHead>Scope</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {alert.decisions.map((decision: Decision, idx: number) => (
                        <TableRow key={idx}>
                          <TableCell>
                            <Badge
                              variant={decision.type === 'ban' ? 'destructive' : 'default'}
                            >
                              {decision.type}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-sm">
                            {decision.value}
                          </TableCell>
                          <TableCell>{decision.duration}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{decision.scope}</Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
            {alert.id && (
              <div className="mt-4">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={(e) => {
                    e.stopPropagation()
                    setInspectOpen(true)
                  }}
                >
                  <Eye className="h-4 w-4 mr-2" />
                  Inspect Full Alert
                </Button>
              </div>
            )}
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
    {alert.id && (
      <AlertInspectDialog
        alertId={alert.id}
        open={inspectOpen}
        onOpenChange={setInspectOpen}
      />
    )}
    </>
  )
}

function AlertInspectDialog({ alertId, open, onOpenChange }: { alertId: number; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ['alert-inspect', alertId],
    queryFn: async () => {
      const response = await crowdsecAPI.inspectAlert(alertId)
      return response.data.data ?? null
    },
    enabled: open,
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Alert #{alertId} Details</DialogTitle>
          <DialogDescription>Full inspection data from CrowdSec LAPI</DialogDescription>
        </DialogHeader>
        {isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">Loading...</div>
        ) : data ? (
          <pre className="p-4 bg-muted rounded-lg text-xs overflow-x-auto whitespace-pre-wrap font-mono">
            {JSON.stringify(data, null, 2)}
          </pre>
        ) : (
          <p className="text-muted-foreground text-sm">No data available</p>
        )}
      </DialogContent>
    </Dialog>
  )
}

export { AlertCard }
export type { AlertCardProps }
