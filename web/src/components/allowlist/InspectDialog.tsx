import type { AllowlistEntry } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { AlertCircle, RefreshCw } from 'lucide-react'

interface InspectData {
  name: string
  description: string
  created_at: string
  updated_at: string
  count: number
  items: AllowlistEntry[]
}

interface InspectDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  allowlistName: string
  data: InspectData | null | undefined
  isLoading: boolean
}

function InspectDialog({ open, onOpenChange, allowlistName, data, isLoading }: InspectDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Inspect Allowlist: {allowlistName}</DialogTitle>
          <DialogDescription>
            View all entries in this allowlist
          </DialogDescription>
        </DialogHeader>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
            <span className="ml-2 text-muted-foreground">Loading entries...</span>
          </div>
        ) : data ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">{data.name}</p>
                <p className="text-sm text-muted-foreground">{data.description}</p>
                <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
                  <span>Created: {new Date(data.created_at).toLocaleString()}</span>
                  <span>Updated: {new Date(data.updated_at).toLocaleString()}</span>
                </div>
              </div>
              <Badge variant="secondary">{data.count} entries</Badge>
            </div>

            {data.items && data.items.length > 0 ? (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Value</TableHead>
                      <TableHead>Created At</TableHead>
                      <TableHead>Expiration</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.items.map((entry: AllowlistEntry, idx: number) => {
                      const isNeverExpires = entry.expiration === '0001-01-01T00:00:00.000Z' || !entry.expiration
                      return (
                        <TableRow key={idx}>
                          <TableCell className="font-mono">{entry.value}</TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {new Date(entry.created_at).toLocaleString()}
                          </TableCell>
                          <TableCell>
                            {isNeverExpires ? (
                              <Badge variant="secondary">Never</Badge>
                            ) : (
                              <span className="text-sm">{new Date(entry.expiration).toLocaleString()}</span>
                            )}
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center border rounded-md">
                <AlertCircle className="h-8 w-8 text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">No entries in this allowlist</p>
              </div>
            )}
          </div>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export { InspectDialog }
export type { InspectDialogProps, InspectData }
