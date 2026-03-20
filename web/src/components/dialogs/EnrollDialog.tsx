import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { ConsoleStatus, EnrollRequest } from '@/lib/api'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { useEnrollmentDialogState } from '@/hooks'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { CheckCircle2 } from 'lucide-react'

interface EnrollDialogProps {
  trigger?: React.ReactNode
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

export default function EnrollDialog({ trigger, open: controlledOpen, onOpenChange: setControlledOpen }: EnrollDialogProps) {
  const [internalOpen, setInternalOpen] = useState(false)
  const isControlled = controlledOpen !== undefined

  const isOpen = isControlled ? controlledOpen : internalOpen

  const [enrollmentKey, setEnrollmentKey] = useState('')
  const [enrollmentStatus, setEnrollmentStatus] = useState<'idle' | 'enrolling' | 'waiting_approval' | 'success'>('idle')

  const queryClient = useQueryClient()

  const isEnrollmentApproved = (status: ConsoleStatus | undefined) =>
    !!status && (status.approved || (status.manual && status.context) || (status.enrolled && status.validated))

  const { data: enrollmentPreferences } = useQuery({
    queryKey: ['crowdsec-enrollment-preferences'],
    queryFn: async () => {
      const response = await api.crowdsec.getEnrollmentPreferences()
      return response.data.data
    },
    enabled: isOpen,
  })

  // Derive disableContext directly from server state — no local state needed.
  const disableContext = enrollmentPreferences?.disable_context ?? false

  // Poll for enrollment status
  const { data: enrollmentData } = useQuery({
    queryKey: ['crowdsec-enrollment-status'],
    queryFn: async () => {
      const response = await api.crowdsec.getStatus()
      return response.data.data ?? null
    },
    refetchInterval: (query) => {
      const data = query.state.data as ConsoleStatus | undefined
      // Poll faster if waiting for approval
      if (data && !isEnrollmentApproved(data)) return 2000
      return 5000
    },
    enabled: isOpen, // Only poll when dialog is open
  })

  const resetEnrollmentForm = useCallback(() => {
    setEnrollmentStatus('idle')
    setEnrollmentKey('')
  }, [])

  const setIsOpen = useCallback((open: boolean) => {
    if (isControlled && setControlledOpen) {
      setControlledOpen(open)
    } else {
      setInternalOpen(open)
    }
    // Reset state when closing (unless successfully enrolled)
    if (!open && enrollmentStatus !== 'success') {
      setTimeout(() => {
        resetEnrollmentForm()
      }, 300)
    }
  }, [enrollmentStatus, isControlled, resetEnrollmentForm, setControlledOpen])

  useEnrollmentDialogState({
    enrollmentData,
    enrollmentStatus,
    isEnrollmentApproved,
    isOpen,
    resetEnrollmentForm,
    setEnrollmentStatus,
    setIsOpen,
  })

  const enrollMutation = useMutation({
    mutationFn: (data: EnrollRequest) => api.crowdsec.enroll(data),
    onSuccess: () => {
      toast.success('Enrollment key submitted. Please approve in CrowdSec Console.')
      setEnrollmentStatus('waiting_approval')
      // Enrollment output available at response.data.data?.output if needed
      queryClient.invalidateQueries({ queryKey: ['crowdsec-enrollment-status'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to submit enrollment key', ErrorContexts.EnrollSubmitKey))
      setEnrollmentStatus('idle')
    },
  })

  const savePreferenceMutation = useMutation({
    mutationFn: (enabled: boolean) =>
      api.crowdsec.updateEnrollmentPreferences({ disable_context: enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crowdsec-enrollment-preferences'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to save enrollment preference', ErrorContexts.EnrollSubmitKey))
    },
  })

  const finalizeMutation = useMutation({
    mutationFn: () => api.crowdsec.finalizeEnrollment(),
    onSuccess: (response) => {
      const status = response.data.data
      queryClient.invalidateQueries({ queryKey: ['crowdsec-enrollment-status'] })

      if (isEnrollmentApproved(status)) {
        setEnrollmentStatus('success')
        toast.success('CrowdSec restarted and enrollment is complete.')
        return
      }

      toast.message('Restart completed. Approval is still pending from CrowdSec Console.')
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to restart CrowdSec', ErrorContexts.EnrollSubmitKey))
    },
  })

  const handleEnroll = (e: React.FormEvent) => {
    e.preventDefault()
    if (!enrollmentKey.trim()) {
      toast.error('Please enter an enrollment key')
      return
    }
    enrollMutation.mutate({ enrollment_key: enrollmentKey.trim(), disable_context: disableContext })
    setEnrollmentStatus('enrolling')
  }

  const handleCancelEnrollment = () => {
    setIsOpen(false)
    resetEnrollmentForm()
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      {trigger && <DialogTrigger asChild>{trigger}</DialogTrigger>}
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Enroll with CrowdSec Console</DialogTitle>
          <DialogDescription>
            Connect your instance to CrowdSec Console for centralized management
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleEnroll} className="space-y-4">
          {enrollmentStatus === 'idle' || enrollmentStatus === 'enrolling' ? (
            <>
              <div className="space-y-2">
                <Label htmlFor="enrollment-key">
                  Enrollment Key <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="enrollment-key"
                  type="text"
                  placeholder="Your CrowdSec Console enrollment key"
                  value={enrollmentKey}
                  onChange={(e) => setEnrollmentKey(e.target.value)}
                  disabled={enrollmentStatus === 'enrolling'}
                />
                <p className="text-xs text-muted-foreground">
                  Get your enrollment key from the CrowdSec Console
                </p>
              </div>
              <div className="flex items-start gap-3 rounded-md border p-3">
                <Checkbox
                  id="disable-context-enroll"
                  checked={disableContext}
                  onCheckedChange={(checked) => {
                    savePreferenceMutation.mutate(checked === true)
                  }}
                  disabled={enrollmentStatus === 'enrolling' || savePreferenceMutation.isPending}
                />
                <div className="space-y-1">
                  <Label htmlFor="disable-context-enroll" className="cursor-pointer">
                    Disable context during enrollment
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Uses <code>cscli console enroll --disable context</code> and stores this preference.
                  </p>
                </div>
              </div>
              <Button
                type="submit"
                className="w-full"
                disabled={enrollmentStatus === 'enrolling'}
              >
                {enrollmentStatus === 'enrolling' ? 'Submitting...' : 'Enroll Instance'}
              </Button>
            </>
          ) : enrollmentStatus === 'waiting_approval' ? (
            <div className="text-center space-y-4 py-4">
              <div className="flex justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
              </div>
              <div>
                <h3 className="font-medium text-lg">Waiting for Approval</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Please go to the CrowdSec Console and approve this instance.
                </p>
              </div>
              <Button
                type="button"
                onClick={() => finalizeMutation.mutate()}
                disabled={finalizeMutation.isPending}
                className="w-full"
              >
                {finalizeMutation.isPending ? 'Restarting CrowdSec...' : 'Restart CrowdSec & Recheck'}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={handleCancelEnrollment}
                className="w-full"
              >
                Cancel
              </Button>
            </div>
          ) : (
            <div className="text-center space-y-4 py-4">
              <div className="flex justify-center">
                <CheckCircle2 className="h-12 w-12 text-emerald-600 dark:text-emerald-400" />
              </div>
              <div>
                <h3 className="font-medium text-lg">Enrollment Successful!</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Your instance has been successfully enrolled and approved.
                </p>
                {enrollmentData && !enrollmentData.management_enabled && (
                  <p className="text-xs text-muted-foreground mt-2">
                    Console management is disabled, but enrollment is complete.
                  </p>
                )}
              </div>
              <Button
                type="button"
                onClick={() => {
                  setIsOpen(false)
                  resetEnrollmentForm()
                }}
                className="w-full"
              >
                Close
              </Button>
            </div>
          )}
        </form>
      </DialogContent>
    </Dialog>
  )
}
