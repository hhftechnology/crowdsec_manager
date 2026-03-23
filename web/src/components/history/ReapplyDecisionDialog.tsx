import { useState } from 'react'
import { useForm, Controller } from 'react-hook-form'
import { toast } from 'sonner'
import { RotateCcw, Loader2 } from 'lucide-react'
import api from '@/lib/api'
import type { DecisionHistoryRecord } from '@/lib/api'
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

interface ReapplyFormValues {
  type: string
  duration: string
  customDuration: string
  reason: string
}

interface ReapplyDecisionDialogProps {
  record: DecisionHistoryRecord | null
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

function getRecordValue(record: DecisionHistoryRecord): string {
  return record.value
}

export function ReapplyDecisionDialog({ record, open, onClose, onSuccess }: ReapplyDecisionDialogProps) {
  const [isLoading, setIsLoading] = useState(false)

  const { control, register, handleSubmit, watch, reset } = useForm<ReapplyFormValues>({
    defaultValues: {
      type: 'ban',
      duration: '24h',
      customDuration: '',
      reason: '',
    },
  })

  const selectedDuration = watch('duration')

  const onSubmit = async (data: ReapplyFormValues) => {
    if (!record) return
    const id = record.id

    const duration = data.duration === 'custom' ? data.customDuration : data.duration
    if (!duration) {
      toast.error('Duration is required')
      return
    }

    setIsLoading(true)
    try {
      await api.crowdsec.reapplyDecision({
        id,
        type: data.type,
        duration,
        reason: data.reason || undefined,
      })
      toast.success(`Decision reapplied: ${getRecordValue(record)} (${data.type}, ${duration})`)
      reset()
      onSuccess()
      onClose()
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } }
      toast.error(axiosError.response?.data?.error || 'Failed to reapply decision')
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
          <DialogTitle>Re-apply Decision</DialogTitle>
          <DialogDescription>
            Re-insert <span className="font-mono font-medium">{record ? getRecordValue(record) : ''}</span> into CrowdSec with a new decision type and duration.
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
            <Label htmlFor="reason">Reason <span className="text-muted-foreground text-xs">(optional)</span></Label>
            <Input
              id="reason"
              {...register('reason')}
              placeholder="Reapplied from history"
            />
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={handleClose} disabled={isLoading}>
              Cancel
            </Button>
            <Button type="submit" disabled={isLoading}>
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RotateCcw className="h-4 w-4 mr-2" />}
              Re-apply
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
