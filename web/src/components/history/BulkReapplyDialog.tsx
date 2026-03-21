import { useState } from 'react'
import { useForm, Controller } from 'react-hook-form'
import { toast } from 'sonner'
import { RotateCcw, Loader2 } from 'lucide-react'
import api from '@/lib/api'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface BulkReapplyFormValues {
  type: string
  duration: string
  customDuration: string
  reason: string
}

interface BulkReapplyDialogProps {
  ids: number[]
  open: boolean
  onClose: () => void
  onSuccess: () => void
}

const DURATION_PRESETS = [
  { value: '1h', label: '1 hour' },
  { value: '4h', label: '4 hours' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: 'permanent', label: 'Permanent' },
  { value: 'custom', label: 'Custom…' },
]

export function BulkReapplyDialog({ ids, open, onClose, onSuccess }: BulkReapplyDialogProps) {
  const [isLoading, setIsLoading] = useState(false)

  const { control, register, handleSubmit, watch, reset } = useForm<BulkReapplyFormValues>({
    defaultValues: {
      type: 'ban',
      duration: '24h',
      customDuration: '',
      reason: '',
    },
  })

  const selectedDuration = watch('duration')

  const onSubmit = async (data: BulkReapplyFormValues) => {
    const duration = data.duration === 'custom' ? data.customDuration : data.duration
    if (!duration) {
      toast.error('Duration is required')
      return
    }

    setIsLoading(true)
    try {
      const response = await api.crowdsec.bulkReapplyDecisions({
        ids,
        type: data.type,
        duration,
        reason: data.reason || undefined,
      })
      const result = response.data.data

      if (result && result.failed > 0) {
        toast.warning(`Re-applied ${result.succeeded} of ${ids.length} decisions (${result.failed} failed)`)
      } else {
        toast.success(`Successfully re-applied ${result?.succeeded ?? ids.length} decisions`)
      }

      reset()
      onSuccess()
      onClose()
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } }
      toast.error(axiosError.response?.data?.error || 'Failed to bulk re-apply decisions')
    } finally {
      setIsLoading(false)
    }
  }

  const handleClose = () => {
    reset()
    onClose()
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) handleClose() }}>
      <DialogContent className="sm:max-w-[420px]">
        <DialogHeader>
          <DialogTitle>Bulk Re-apply Decisions</DialogTitle>
          <DialogDescription>
            Re-insert <span className="font-semibold">{ids.length}</span> selected decision{ids.length !== 1 ? 's' : ''} into CrowdSec.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {/* Type */}
          <div className="space-y-2">
            <Label>Decision Type</Label>
            <Controller
              name="type"
              control={control}
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ban">Ban</SelectItem>
                    <SelectItem value="captcha">Captcha</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
          </div>

          {/* Duration */}
          <div className="space-y-2">
            <Label>Duration</Label>
            <Controller
              name="duration"
              control={control}
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select duration" />
                  </SelectTrigger>
                  <SelectContent>
                    {DURATION_PRESETS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
            {selectedDuration === 'custom' && (
              <Input
                {...register('customDuration')}
                placeholder="e.g. 2h, 14d, 3mo"
                className="mt-1"
              />
            )}
          </div>

          {/* Reason */}
          <div className="space-y-2">
            <Label htmlFor="bulk-reason">Reason <span className="text-muted-foreground text-xs">(optional)</span></Label>
            <Input
              id="bulk-reason"
              {...register('reason')}
              placeholder="Bulk reapply from history"
            />
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={handleClose} disabled={isLoading}>
              Cancel
            </Button>
            <Button type="submit" disabled={isLoading}>
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RotateCcw className="h-4 w-4 mr-2" />}
              Re-apply {ids.length} Decision{ids.length !== 1 ? 's' : ''}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
