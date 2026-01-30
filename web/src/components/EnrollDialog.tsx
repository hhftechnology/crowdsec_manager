import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { EnrollRequest } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { CheckCircle2, AlertCircle } from 'lucide-react'

interface EnrollDialogProps {
  trigger?: React.ReactNode
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

type EnrollmentStatusType = 'idle' | 'enrolling' | 'waiting_approval' | 'needs_enable' | 'success'

export default function EnrollDialog({ trigger, open: controlledOpen, onOpenChange: setControlledOpen }: EnrollDialogProps) {
  const [internalOpen, setInternalOpen] = useState(false)
  const isControlled = controlledOpen !== undefined

  const isOpen = isControlled ? controlledOpen : internalOpen
  const setIsOpen = (open: boolean) => {
    if (isControlled && setControlledOpen) {
      setControlledOpen(open)
    } else {
      setInternalOpen(open)
    }
  }

  const [enrollmentKey, setEnrollmentKey] = useState('')
  const [enrollmentStatus, setEnrollmentStatus] = useState<EnrollmentStatusType>('idle')

  const queryClient = useQueryClient()

  // Poll for enrollment status
  const { data: enrollmentData } = useQuery({
    queryKey: ['crowdsec-enrollment-status'],
    queryFn: async () => {
      const response = await api.crowdsec.getStatus()
      return response.data.data
    },
    refetchInterval: (query) => {
      const data = query.state.data
      // Poll faster if waiting for approval or needs enable
      if (data?.enrolled && !data.console_management) return 2000
      return 5000
    },
    enabled: isOpen, // Only poll when dialog is open
  })

  // Sync state with data
  useEffect(() => {
    if (!enrollmentData) return

    // console_management true = fully validated and enabled
    if (enrollmentData.console_management) {
      // Successfully enrolled and console management is enabled
      if (enrollmentStatus !== 'success') {
        setEnrollmentStatus('success')
        // Only show toast if we were previously enrolling or waiting
        if (enrollmentStatus === 'enrolling' || enrollmentStatus === 'waiting_approval' || enrollmentStatus === 'needs_enable') {
          toast.success('CrowdSec instance successfully enrolled and validated!')
          setTimeout(() => {
            setIsOpen(false)
            setEnrollmentStatus('idle')
            setEnrollmentKey('')
          }, 2000)
        }
      }
    } else if (enrollmentData.enrolled && !enrollmentData.console_management) {
      // Enrolled but console_management is false - needs to enable it
      if (enrollmentStatus === 'idle' || enrollmentStatus === 'waiting_approval') {
        setEnrollmentStatus('needs_enable')
      }
    } else if (!enrollmentData.enrolled) {
      // Not enrolled at all
      if (enrollmentStatus !== 'enrolling') {
        setEnrollmentStatus('idle')
      }
    }
    // Don't reset to idle automatically during enrolling state
  }, [enrollmentData, enrollmentStatus])

  const enrollMutation = useMutation({
    mutationFn: (data: EnrollRequest) => api.crowdsec.enroll(data),
    onSuccess: (response: { data: { data?: { output?: string; console_management_enabled?: boolean } } }) => {
      toast.success('Enrollment key submitted. Please approve in CrowdSec Console.')
      setEnrollmentStatus('waiting_approval')
      if (response.data.data?.output) {
        console.log('Enrollment output:', response.data.data.output)
      }
      queryClient.invalidateQueries({ queryKey: ['crowdsec-enrollment-status'] })
    },
    onError: () => {
      toast.error('Failed to submit enrollment key')
      setEnrollmentStatus('idle')
    },
  })

  const enableConsoleMutation = useMutation({
    mutationFn: () => api.crowdsec.enableConsoleManagement(),
    onSuccess: () => {
      toast.success('Console management enabled. Restarting CrowdSec may be required.')
      queryClient.invalidateQueries({ queryKey: ['crowdsec-enrollment-status'] })
      // After enabling, the next poll should show console_management: true
    },
    onError: () => {
      toast.error('Failed to enable console management')
    },
  })

  const handleEnroll = (e: React.FormEvent) => {
    e.preventDefault()
    if (!enrollmentKey.trim()) {
      toast.error('Please enter an enrollment key')
      return
    }
    enrollMutation.mutate({ enrollment_key: enrollmentKey.trim() })
    setEnrollmentStatus('enrolling')
  }

  const handleEnableConsoleManagement = () => {
    enableConsoleMutation.mutate()
  }

  const handleCancelEnrollment = () => {
    setIsOpen(false)
    setEnrollmentStatus('idle')
    setEnrollmentKey('')
  }

  // Check status when dialog first opens
  useEffect(() => {
    if (isOpen && enrollmentData && enrollmentStatus === 'idle') {
      // If console_management is enabled, show success immediately
      if (enrollmentData.console_management) {
        setEnrollmentStatus('success')
      }
      // If enrolled but console_management is false, show needs_enable state
      else if (enrollmentData.enrolled && !enrollmentData.console_management) {
        setEnrollmentStatus('needs_enable')
      }
    }
  }, [isOpen, enrollmentData, enrollmentStatus])

  // Reset state when dialog closes (unless successfully enrolled)
  useEffect(() => {
    if (!isOpen && enrollmentStatus !== 'success') {
      // Delay reset to allow dialog close animation
      const timer = setTimeout(() => {
        setEnrollmentStatus('idle')
        setEnrollmentKey('')
      }, 300)
      return () => clearTimeout(timer)
    }
  }, [isOpen, enrollmentStatus])

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
                variant="outline"
                onClick={handleCancelEnrollment}
                className="w-full"
              >
                Cancel
              </Button>
            </div>
          ) : enrollmentStatus === 'needs_enable' ? (
            <div className="text-center space-y-4 py-4">
              <div className="flex justify-center">
                <AlertCircle className="h-12 w-12 text-yellow-500" />
              </div>
              <div>
                <h3 className="font-medium text-lg">Almost There!</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Your instance is enrolled. Click below to enable Console Management,
                  then restart CrowdSec to complete the connection.
                </p>
              </div>
              <Button
                type="button"
                onClick={handleEnableConsoleManagement}
                className="w-full"
                disabled={enableConsoleMutation.isPending}
              >
                {enableConsoleMutation.isPending ? 'Enabling...' : 'Enable Console Management'}
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
                <CheckCircle2 className="h-12 w-12 text-green-500" />
              </div>
              <div>
                <h3 className="font-medium text-lg">Enrollment Successful!</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Your instance has been successfully enrolled and validated.
                </p>
              </div>
              <Button
                type="button"
                onClick={() => {
                  setIsOpen(false)
                  setEnrollmentStatus('idle')
                  setEnrollmentKey('')
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
