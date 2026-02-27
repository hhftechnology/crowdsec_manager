import { Check, X, Loader2, SkipForward, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { StepResult } from '@/lib/api/types'

interface StepProgressProps {
  steps: StepResult[]
  isRunning?: boolean
  currentStep?: number
  retryingStep?: number
  onRetryStep?: (step: number) => void
}

export function StepProgress({ steps, isRunning = false, currentStep, retryingStep, onRetryStep }: StepProgressProps) {
  return (
    <div className="space-y-3">
      {steps.map((step) => (
        <div
          key={step.step}
          className="flex items-center gap-3 rounded-lg border p-3"
        >
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2">
            {retryingStep === step.step ? (
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
            ) : step.skipped ? (
              <SkipForward className="h-4 w-4 text-muted-foreground" />
            ) : step.success ? (
              <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
            ) : step.error ? (
              <X className="h-4 w-4 text-destructive" />
            ) : isRunning && currentStep === step.step ? (
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
            ) : (
              <span className="text-xs text-muted-foreground">{step.step}</span>
            )}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium">{step.name}</p>
            {step.error && (
              <p className="text-xs text-destructive mt-1">{step.error}</p>
            )}
            {step.skipped && (
              <p className="text-xs text-muted-foreground mt-1">Skipped</p>
            )}
          </div>
          {!step.success && step.error && onRetryStep && retryingStep !== step.step && (
            <Button
              variant="ghost"
              size="sm"
              className="shrink-0"
              onClick={() => onRetryStep(step.step)}
              disabled={retryingStep !== undefined}
            >
              <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
              Retry
            </Button>
          )}
        </div>
      ))}
    </div>
  )
}
