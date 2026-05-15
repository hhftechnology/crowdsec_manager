import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '@/lib/api'
import { cn } from '@/lib/utils'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'

interface UseLogProcessingControlInput {
  onDisabled?: () => void
}

export function useLogProcessingControl(input: UseLogProcessingControlInput = {}) {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: ['logs-processing'],
    queryFn: async () => {
      const response = await api.logs.getProcessing()
      return response.data.data?.enabled ?? true
    },
    staleTime: 30_000,
  })

  const mutation = useMutation({
    mutationFn: async (enabled: boolean) => {
      const response = await api.logs.updateProcessing({ enabled })
      return response.data.data?.enabled ?? enabled
    },
    onSuccess: (enabled) => {
      queryClient.setQueryData(['logs-processing'], enabled)
      queryClient.invalidateQueries({ queryKey: ['logs-dashboard'] })
      queryClient.invalidateQueries({ queryKey: ['logs-crowdsec'] })
      queryClient.invalidateQueries({ queryKey: ['logs-traefik'] })
      if (!enabled) input.onDisabled?.()
      toast.success(enabled ? 'Log processing enabled' : 'Log processing disabled')
    },
    onError: () => {
      toast.error('Failed to update log processing')
    },
  })

  return {
    enabled: query.data ?? true,
    isLoading: query.isLoading,
    isUpdating: mutation.isPending,
    setEnabled: mutation.mutate,
  }
}

export type LogProcessingControl = ReturnType<typeof useLogProcessingControl>

export function LogProcessingToggle({
  control,
  className,
}: {
  control: LogProcessingControl
  className?: string
}) {
  const [confirmOpen, setConfirmOpen] = useState(false)

  const handleCheckedChange = (checked: boolean) => {
    if (checked && !control.enabled) {
      setConfirmOpen(true)
      return
    }
    control.setEnabled(checked)
  }

  return (
    <>
      <div className={cn('flex items-center justify-between gap-3 rounded-lg border bg-card px-3 py-2', className)}>
        <div className="min-w-0">
          <Label htmlFor="log-processing-toggle" className="text-sm font-medium">
            Log processing
          </Label>
          <p className="text-xs text-muted-foreground">
            Controls Traefik and CrowdSec log reads, dashboards, and streams.
          </p>
        </div>
        <Switch
          id="log-processing-toggle"
          checked={control.enabled}
          disabled={control.isLoading || control.isUpdating}
          onCheckedChange={handleCheckedChange}
          aria-label="Toggle log processing"
        />
      </div>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Enable log processing?</AlertDialogTitle>
            <AlertDialogDescription>
              Keeping log processing enabled lets the dashboards, raw logs, structured logs, and live streams read Traefik and CrowdSec containers. This can use more CPU, memory, and Docker API resources.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={control.isUpdating}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={control.isUpdating}
              onClick={() => {
                control.setEnabled(true)
                setConfirmOpen(false)
              }}
            >
              Enable
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
