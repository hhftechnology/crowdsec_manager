import type { ReactNode } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Check, ChevronLeft, ChevronRight, Loader2, AlertCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface WizardStep {
  id: string
  title: string
  description?: string
  content: ReactNode
  /** Controls whether the Next/Complete button is enabled. Defaults to true when omitted. */
  canProceed?: boolean
  optional?: boolean
}

interface FeatureWizardProps {
  title: string
  description?: string
  icon?: ReactNode
  steps: WizardStep[]
  currentStep: number
  onStepChange: (step: number) => void
  onComplete?: () => void
  isProcessing?: boolean
  completedSteps?: Set<string>
  errorSteps?: Set<string>
}

export function FeatureWizard({
  icon,
  steps,
  currentStep,
  onStepChange,
  onComplete,
  isProcessing = false,
  completedSteps = new Set(),
  errorSteps = new Set(),
}: FeatureWizardProps) {
  const isLastStep = currentStep === steps.length - 1
  const isFirstStep = currentStep === 0
  const current = steps[currentStep]

  return (
    <div className="space-y-6">
      {/* Step indicators */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2">
        {steps.map((step, idx) => {
          const isActive = idx === currentStep
          const isCompleted = completedSteps.has(step.id)
          const hasError = errorSteps.has(step.id)

          return (
            <div key={step.id} className="flex items-center gap-2">
              {idx > 0 && (
                <Separator className="w-8 shrink-0" />
              )}
              <button
                onClick={() => onStepChange(idx)}
                disabled={isProcessing}
                className={cn(
                  'flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors whitespace-nowrap',
                  isActive && 'bg-primary text-primary-foreground',
                  !isActive && isCompleted && 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400',
                  !isActive && hasError && 'bg-destructive/10 text-destructive',
                  !isActive && !isCompleted && !hasError && 'bg-muted text-muted-foreground hover:bg-muted/80',
                )}
              >
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-xs font-medium">
                  {isCompleted ? (
                    <Check className="h-3.5 w-3.5" />
                  ) : hasError ? (
                    <AlertCircle className="h-3.5 w-3.5" />
                  ) : isProcessing && isActive ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    idx + 1
                  )}
                </span>
                {step.title}
              </button>
            </div>
          )
        })}
      </div>

      {/* Step content */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            {icon}
            <div>
              <CardTitle>{current?.title}</CardTitle>
              {current?.description && (
                <CardDescription>{current.description}</CardDescription>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {current?.content}
        </CardContent>
      </Card>

      {/* Navigation */}
      <div className="flex items-center justify-between">
        <Button
          variant="outline"
          onClick={() => onStepChange(currentStep - 1)}
          disabled={isFirstStep || isProcessing}
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Back
        </Button>

        <div className="flex items-center gap-2">
          {current?.optional && !isLastStep && (
            <Button
              variant="ghost"
              onClick={() => onStepChange(currentStep + 1)}
              disabled={isProcessing}
            >
              Skip
            </Button>
          )}
          {isLastStep ? (
            <Button
              onClick={onComplete}
              disabled={isProcessing || current?.canProceed === false}
            >
              {isProcessing ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Processing...
                </>
              ) : (
                'Complete'
              )}
            </Button>
          ) : (
            <Button
              onClick={() => onStepChange(currentStep + 1)}
              disabled={isProcessing || current?.canProceed === false}
            >
              Next
              <ChevronRight className="h-4 w-4 ml-1" />
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}
