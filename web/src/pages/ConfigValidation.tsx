import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { configValidationAPI } from '@/lib/api/config-validation'
import type { ConfigValidationReport, ConfigSnapshot } from '@/lib/api/config-validation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { toast } from 'sonner'
import {
  ShieldCheck,
  RefreshCw,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Trash2,
  Camera,
  Check,
} from 'lucide-react'

function statusBadge(status: string) {
  switch (status) {
    case 'match':
      return <Badge variant="default" className="bg-emerald-600"><CheckCircle2 className="h-3 w-3 mr-1" />Match</Badge>
    case 'drift':
      return <Badge variant="destructive"><AlertTriangle className="h-3 w-3 mr-1" />Drift</Badge>
    case 'missing':
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Missing</Badge>
    case 'no_snapshot':
      return <Badge variant="secondary">No Snapshot</Badge>
    default:
      return <Badge variant="outline">{status}</Badge>
  }
}

export default function ConfigValidation() {
  const queryClient = useQueryClient()
  const [validating, setValidating] = useState(false)

  const { data: report, refetch: refetchReport } = useQuery({
    queryKey: ['config-validation'],
    queryFn: async () => {
      const response = await configValidationAPI.validate()
      return response.data.data as ConfigValidationReport
    },
    enabled: false,
  })

  const { data: snapshots, refetch: refetchSnapshots } = useQuery({
    queryKey: ['config-snapshots'],
    queryFn: async () => {
      const response = await configValidationAPI.getSnapshots()
      return (response.data.data ?? []) as ConfigSnapshot[]
    },
  })

  const handleValidate = async () => {
    setValidating(true)
    try {
      await refetchReport()
    } finally {
      setValidating(false)
    }
  }

  const snapshotAll = useMutation({
    mutationFn: () => configValidationAPI.snapshotAll(),
    onSuccess: () => {
      toast.success('All configs snapshotted')
      queryClient.invalidateQueries({ queryKey: ['config-snapshots'] })
    },
    onError: () => toast.error('Failed to snapshot configs'),
  })

  const restore = useMutation({
    mutationFn: (type: string) => configValidationAPI.restore(type),
    onSuccess: (_, type) => {
      toast.success(`Restored config: ${type}`)
      refetchReport()
    },
    onError: () => toast.error('Failed to restore config'),
  })

  const accept = useMutation({
    mutationFn: (type: string) => configValidationAPI.accept(type),
    onSuccess: (_, type) => {
      toast.success(`Accepted current config as baseline: ${type}`)
      refetchReport()
      refetchSnapshots()
    },
    onError: () => toast.error('Failed to accept config'),
  })

  const deleteSnapshot = useMutation({
    mutationFn: (type: string) => configValidationAPI.deleteSnapshot(type),
    onSuccess: (_, type) => {
      toast.success(`Snapshot deleted: ${type}`)
      refetchSnapshots()
      refetchReport()
    },
    onError: () => toast.error('Failed to delete snapshot'),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Config Validation</h1>
          <p className="text-muted-foreground mt-2">
            Detect config drift, recover lost configurations, and manage snapshots
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => snapshotAll.mutate()} disabled={snapshotAll.isPending}>
            <Camera className="h-4 w-4 mr-2" />
            Snapshot All
          </Button>
          <Button onClick={handleValidate} disabled={validating}>
            {validating ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <ShieldCheck className="h-4 w-4 mr-2" />
            )}
            Validate Now
          </Button>
        </div>
      </div>

      {/* Validation Results */}
      {report && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {report.overall === 'ok' ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-destructive" />
              )}
              Validation Results
            </CardTitle>
            <CardDescription>
              Last validated: {new Date(report.timestamp).toLocaleString()} &mdash;
              Overall: {report.overall === 'ok' ? 'All configs match' : 'Issues detected'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Config Type</TableHead>
                  <TableHead>File Path</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Message</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {report.results.map((result) => (
                  <TableRow key={result.config_type}>
                    <TableCell className="font-medium">{result.config_type}</TableCell>
                    <TableCell className="font-mono text-xs">{result.file_path}</TableCell>
                    <TableCell>{statusBadge(result.status)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{result.message}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex gap-1 justify-end">
                        {(result.status === 'missing' || result.status === 'drift') && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => restore.mutate(result.config_type)}
                            disabled={restore.isPending}
                          >
                            <RotateCcw className="h-3 w-3 mr-1" />
                            Restore
                          </Button>
                        )}
                        {result.status === 'drift' && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => accept.mutate(result.config_type)}
                            disabled={accept.isPending}
                          >
                            <Check className="h-3 w-3 mr-1" />
                            Accept
                          </Button>
                        )}
                        {result.status !== 'no_snapshot' && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => deleteSnapshot.mutate(result.config_type)}
                            disabled={deleteSnapshot.isPending}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Stored Snapshots */}
      <Card>
        <CardHeader>
          <CardTitle>Stored Snapshots</CardTitle>
          <CardDescription>
            Configuration snapshots stored in the database for drift detection and recovery
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!snapshots || snapshots.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No snapshots stored yet. Click "Snapshot All" or "Validate Now" to create initial snapshots.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Config Type</TableHead>
                  <TableHead>File Path</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Hash</TableHead>
                  <TableHead>Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshots.map((snapshot) => (
                  <TableRow key={snapshot.id}>
                    <TableCell className="font-medium">{snapshot.config_type}</TableCell>
                    <TableCell className="font-mono text-xs">{snapshot.file_path}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{snapshot.source}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{snapshot.content_hash.substring(0, 12)}...</TableCell>
                    <TableCell className="text-sm">{new Date(snapshot.updated_at).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
