import { useState, useCallback, useEffect } from 'react'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { CheckCircle2, XCircle } from 'lucide-react'

interface ValidationResult {
  valid: boolean
  message: string
}

interface IPValidationInputProps {
  value: string
  onChange: (value: string) => void
  onValidation?: (result: ValidationResult) => void
  allowCIDR?: boolean
  placeholder?: string
  className?: string
}

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_REGEX = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
const IPV4_CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
const IPV6_CIDR_REGEX = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\/\d{1,3}$/

function validateIPv4(ip: string): boolean {
  if (!IPV4_REGEX.test(ip)) return false
  return ip.split('.').every((octet) => {
    const num = parseInt(octet, 10)
    return num >= 0 && num <= 255
  })
}

function validateIPv6(ip: string): boolean {
  return IPV6_REGEX.test(ip)
}

function validateCIDR(value: string): boolean {
  if (IPV4_CIDR_REGEX.test(value)) {
    const [ip, prefix] = value.split('/')
    if (!validateIPv4(ip)) return false
    const prefixNum = parseInt(prefix, 10)
    return prefixNum >= 0 && prefixNum <= 32
  }
  if (IPV6_CIDR_REGEX.test(value)) {
    const lastSlash = value.lastIndexOf('/')
    const ip = value.substring(0, lastSlash)
    const prefix = value.substring(lastSlash + 1)
    if (!validateIPv6(ip)) return false
    const prefixNum = parseInt(prefix, 10)
    return prefixNum >= 0 && prefixNum <= 128
  }
  return false
}

function validateInput(value: string, allowCIDR: boolean): ValidationResult {
  if (!value.trim()) {
    return { valid: false, message: '' }
  }

  if (allowCIDR && value.includes('/')) {
    if (validateCIDR(value)) {
      return { valid: true, message: 'Valid CIDR notation' }
    }
    return { valid: false, message: 'Invalid CIDR notation' }
  }

  if (validateIPv4(value)) {
    return { valid: true, message: 'Valid IPv4 address' }
  }

  if (validateIPv6(value)) {
    return { valid: true, message: 'Valid IPv6 address' }
  }

  return { valid: false, message: 'Invalid IP address' }
}

function IPValidationInput({
  value,
  onChange,
  onValidation,
  allowCIDR = false,
  placeholder,
  className,
}: IPValidationInputProps) {
  const [validation, setValidation] = useState<ValidationResult>({ valid: false, message: '' })

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      onChange(e.target.value)
    },
    [onChange]
  )

  useEffect(() => {
    const result = validateInput(value, allowCIDR)
    setValidation(result)
    onValidation?.(result)
  }, [value, allowCIDR, onValidation])

  const defaultPlaceholder = allowCIDR
    ? 'Enter IP address or CIDR (e.g., 192.168.1.0/24)'
    : 'Enter IP address (e.g., 192.168.1.1)'

  return (
    <div className={cn('space-y-1', className)}>
      <div className="relative">
        <Input
          value={value}
          onChange={handleChange}
          placeholder={placeholder ?? defaultPlaceholder}
          className={cn(
            value.trim() && (validation.valid
              ? 'border-emerald-500 focus-visible:ring-emerald-500'
              : 'border-destructive focus-visible:ring-destructive')
          )}
        />
        {value.trim() && (
          <div className="absolute right-3 top-1/2 -translate-y-1/2">
            {validation.valid ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <XCircle className="h-4 w-4 text-destructive" />
            )}
          </div>
        )}
      </div>
      {value.trim() && validation.message && (
        <p
          className={cn(
            'text-xs',
            validation.valid ? 'text-emerald-600 dark:text-emerald-400' : 'text-destructive'
          )}
        >
          {validation.message}
        </p>
      )}
    </div>
  )
}

export { IPValidationInput }
export type { IPValidationInputProps, ValidationResult }
