import { useEffect, useMemo } from 'react'

interface ValidationResult {
  valid: boolean
  message: string
}

interface UseValidationResultInput {
  allowCIDR: boolean
  onValidation?: (result: ValidationResult) => void
  validate: (value: string, allowCIDR: boolean) => ValidationResult
  value: string
}

export function useValidationResult({
  allowCIDR,
  onValidation,
  validate,
  value,
}: UseValidationResultInput): ValidationResult {
  const validation = useMemo(() => validate(value, allowCIDR), [allowCIDR, validate, value])

  useEffect(() => {
    onValidation?.(validation)
  }, [onValidation, validation])

  return validation
}

export type { ValidationResult }
