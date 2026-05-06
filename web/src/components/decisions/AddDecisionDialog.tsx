import { useState } from 'react'
import { useForm, Controller } from 'react-hook-form'
import { toast } from 'sonner'
import { Plus, Loader2 } from 'lucide-react'
import api, { AddDecisionRequest } from '@/lib/api'
import { getErrorDetails, getErrorMessage } from '@/lib/api/errors'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
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
import { DurationField } from './DurationField'

interface AddDecisionDialogProps {
  onSuccess: () => void
}

type SelectorMode = 'ip' | 'range' | 'scope'

interface AddDecisionFormValues extends AddDecisionRequest {
  selectorValue: string
}

const defaultValues: AddDecisionFormValues = {
  type: 'ban',
  scope: 'ip',
  selectorValue: '',
  duration: '4h',
  reason: 'Manual decision via UI',
  origin: 'cscli',
}

export function AddDecisionDialog({ onSuccess }: AddDecisionDialogProps) {
  const [open, setOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [selectorMode, setSelectorMode] = useState<SelectorMode>('ip')

  const { control, register, handleSubmit, reset, setValue, formState: { errors } } = useForm<AddDecisionFormValues>({
    defaultValues,
  })

  const onSubmit = async (data: AddDecisionFormValues) => {
    const selectorValue = data.selectorValue.trim()
    const payload: AddDecisionRequest = {
      type: data.type,
      duration: data.duration,
      reason: data.reason || undefined,
      origin: data.origin || undefined,
    }

    if (selectorMode === 'ip') {
      payload.ip = selectorValue
    } else if (selectorMode === 'range') {
      payload.range = selectorValue
    } else {
      payload.scope = data.scope
      payload.value = selectorValue
    }

    setIsLoading(true)
    try {
      await api.crowdsec.addDecision(payload)
      toast.success('Decision added successfully')
      setOpen(false)
      reset(defaultValues)
      setSelectorMode('ip')
      onSuccess()
    } catch (error: unknown) {
      toast.error(getErrorMessage(error, 'Failed to add decision'), {
        description: getErrorDetails(error),
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4" />
          Add Decision
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Add New Decision</DialogTitle>
          <DialogDescription>
            Manually add a decision to CrowdSec.
          </DialogDescription>
        </DialogHeader>
        
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="selector-mode">Selector</Label>
            <Select value={selectorMode} onValueChange={(value) => setSelectorMode(value as SelectorMode)}>
              <SelectTrigger id="selector-mode">
                <SelectValue placeholder="Select selector" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ip">IP</SelectItem>
                <SelectItem value="range">Range</SelectItem>
                <SelectItem value="scope">Scope + value</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="selectorValue">Value</Label>
            <Input
              id="selectorValue"
              placeholder={selectorMode === 'range' ? '10.0.0.0/24' : '1.2.3.4'}
              {...register('selectorValue', { required: 'Value is required' })}
            />
            {errors.selectorValue && <p className="text-sm text-destructive">{errors.selectorValue.message}</p>}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className={selectorMode === 'scope' ? 'space-y-2' : 'hidden'}>
              <Label htmlFor="scope">Scope</Label>
              <Controller
                name="scope"
                control={control}
                render={({ field }) => (
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select scope" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ip">IP</SelectItem>
                      <SelectItem value="range">Range</SelectItem>
                      <SelectItem value="username">Username</SelectItem>
                      <SelectItem value="country">Country</SelectItem>
                      <SelectItem value="as">AS</SelectItem>
                    </SelectContent>
                  </Select>
                )}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="type">Type</Label>
              <Controller
                name="type"
                control={control}
                render={({ field }) => (
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
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
          </div>

          <div className="space-y-2">
            <div className="flex flex-wrap gap-1.5 pb-1">
              {[
                { label: '1h', value: '1h' },
                { label: '4h', value: '4h' },
                { label: '24h', value: '24h' },
                { label: '7d', value: '7d' },
                { label: '30d', value: '30d' },
                { label: 'Permanent', value: '0' },
              ].map((preset) => (
                <Button
                  key={preset.value}
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-7 text-xs px-2"
                  onClick={() => setValue('duration', preset.value)}
                >
                  {preset.label}
                </Button>
              ))}
            </div>
            <Controller
              name="duration"
              control={control}
              render={({ field }) => (
                <DurationField value={field.value || ''} onChange={field.onChange} />
              )}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="origin">Origin</Label>
            <Input
              id="origin"
              placeholder="cscli"
              {...register('origin')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="reason">Reason</Label>
            <Input 
              id="reason" 
              placeholder="Reason for decision" 
              {...register('reason')} 
            />
          </div>

          <DialogFooter>
            <Button type="submit" disabled={isLoading}>
              {isLoading && <Loader2 className="h-4 w-4 animate-spin" />}
              Add Decision
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
