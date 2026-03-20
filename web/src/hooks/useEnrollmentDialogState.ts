import { useEffect } from 'react'
import { toast } from 'sonner'
import type { ConsoleStatus } from '@/lib/api'

type EnrollmentStatus = 'idle' | 'enrolling' | 'waiting_approval' | 'success'

interface UseEnrollmentDialogStateInput {
  enrollmentData: ConsoleStatus | null | undefined
  enrollmentStatus: EnrollmentStatus
  isEnrollmentApproved: (status: ConsoleStatus | undefined) => boolean
  isOpen: boolean
  resetEnrollmentForm: () => void
  setEnrollmentStatus: (status: EnrollmentStatus) => void
  setIsOpen: (open: boolean) => void
}

export function useEnrollmentDialogState({
  enrollmentData,
  enrollmentStatus,
  isEnrollmentApproved,
  isOpen,
  resetEnrollmentForm,
  setEnrollmentStatus,
  setIsOpen,
}: UseEnrollmentDialogStateInput): void {
  useEffect(() => {
    if (!enrollmentData) return

    if (isEnrollmentApproved(enrollmentData) && enrollmentStatus !== 'success') {
      setEnrollmentStatus('success')
      if (enrollmentStatus === 'enrolling' || enrollmentStatus === 'waiting_approval') {
        toast.success('CrowdSec instance successfully enrolled and approved!')
        setTimeout(() => {
          setIsOpen(false)
          resetEnrollmentForm()
        }, 2000)
      }
    }
  }, [
    enrollmentData,
    enrollmentStatus,
    isEnrollmentApproved,
    resetEnrollmentForm,
    setEnrollmentStatus,
    setIsOpen,
  ])

  useEffect(() => {
    if (isOpen && enrollmentData && enrollmentStatus === 'idle') {
      if (isEnrollmentApproved(enrollmentData)) {
        setEnrollmentStatus('success')
      } else if (enrollmentData.manual) {
        setEnrollmentStatus('waiting_approval')
      }
    }
  }, [enrollmentData, enrollmentStatus, isEnrollmentApproved, isOpen, setEnrollmentStatus])
}
