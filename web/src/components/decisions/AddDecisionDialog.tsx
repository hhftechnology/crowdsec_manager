import { useState } from 'react'
import { useForm, Controller } from 'react-hook-form'
import { toast } from 'sonner'
import { Plus, Loader2 } from 'lucide-react'
import api, { AddDecisionRequest } from '@/lib/api'
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

interface AddDecisionDialogProps {
  onSuccess: () => void
}

export function AddDecisionDialog({ onSuccess }: AddDecisionDialogProps) {
  const [open, setOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  const { control, register, handleSubmit, reset, formState: { errors } } = useForm<AddDecisionRequest>({
    defaultValues: {
      type: 'ban',
      scope: 'ip',
      duration: '4h',
      reason: 'Manual decision via UI',
    },
  })

  const onSubmit = async (data: AddDecisionRequest) => {
    setIsLoading(true)
    try {
      await api.crowdsec.addDecision(data)
      toast.success('Decision added successfully')
      setOpen(false)
      reset()
      onSuccess()
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to add decision')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 h-4 w-4" />
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
            <Label htmlFor="value">Value (IP, Range, etc.)</Label>
            <Input 
              id="value" 
              placeholder="1.2.3.4" 
              {...register('value', { required: 'Value is required' })} 
            />
            {errors.value && <p className="text-sm text-destructive">{errors.value.message}</p>}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
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
            <Label htmlFor="duration">Duration</Label>
            <Input 
              id="duration" 
              placeholder="4h" 
              {...register('duration')} 
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
              {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Add Decision
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
