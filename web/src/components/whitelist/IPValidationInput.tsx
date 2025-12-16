import { useState, useEffect } from 'react'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { 
  CheckCircle, 
  XCircle, 
  AlertTriangle 
} from 'lucide-react'

interface IPValidationInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  label?: string
  type?: 'ip' | 'cidr'
  helperText?: string
  required?: boolean
}

export function IPValidationInput({
  value,
  onChange,
  placeholder = '192.168.1.100',
  label = 'IP Address',
  type = 'ip',
  helperText,
  required = false
}: IPValidationInputProps) {
  const [isValid, setIsValid] = useState<boolean | null>(null)
  const [validationMessage, setValidationMessage] = useState<string>('')

  const validateIP = (ip: string): { valid: boolean; message: string } => {
    if (!ip.trim()) {
      return { valid: false, message: 'IP address is required' }
    }

    // IPv4 validation
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    
    if (ipv4Regex.test(ip)) {
      // Check for reserved ranges
      const parts = ip.split('.').map(Number)
      
      // Private ranges
      if (
        (parts[0] === 10) ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168)
      ) {
        return { valid: true, message: 'Valid private IP address' }
      }
      
      // Localhost
      if (parts[0] === 127) {
        return { valid: true, message: 'Valid localhost IP address' }
      }
      
      // Link-local
      if (parts[0] === 169 && parts[1] === 254) {
        return { valid: true, message: 'Valid link-local IP address' }
      }
      
      return { valid: true, message: 'Valid public IP address' }
    }

    // IPv6 basic validation (simplified)
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/
    if (ipv6Regex.test(ip)) {
      return { valid: true, message: 'Valid IPv6 address' }
    }

    return { valid: false, message: 'Invalid IP address format' }
  }

  const validateCIDR = (cidr: string): { valid: boolean; message: string } => {
    if (!cidr.trim()) {
      return { valid: false, message: 'CIDR range is required' }
    }

    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$/
    
    if (!cidrRegex.test(cidr)) {
      return { valid: false, message: 'Invalid CIDR format (use IP/prefix like 192.168.1.0/24)' }
    }

    const [ip, prefix] = cidr.split('/')
    const prefixNum = parseInt(prefix, 10)
    
    // Validate the IP part
    const ipValidation = validateIP(ip)
    if (!ipValidation.valid) {
      return { valid: false, message: `Invalid IP in CIDR: ${ipValidation.message}` }
    }

    // Validate prefix
    if (prefixNum < 0 || prefixNum > 32) {
      return { valid: false, message: 'Prefix must be between 0 and 32' }
    }

    // Check for common CIDR ranges
    if (prefixNum >= 24) {
      return { valid: true, message: `Valid CIDR range (${Math.pow(2, 32 - prefixNum)} addresses)` }
    } else if (prefixNum >= 16) {
      return { valid: true, message: `Valid CIDR range (${Math.pow(2, 32 - prefixNum).toLocaleString()} addresses)` }
    } else {
      return { valid: true, message: `Large CIDR range (${Math.pow(2, 32 - prefixNum).toLocaleString()} addresses)` }
    }
  }

  useEffect(() => {
    if (!value.trim()) {
      setIsValid(null)
      setValidationMessage('')
      return
    }

    const validation = type === 'cidr' ? validateCIDR(value) : validateIP(value)
    setIsValid(validation.valid)
    setValidationMessage(validation.message)
  }, [value, type])

  const getValidationIcon = () => {
    if (isValid === null) return null
    if (isValid) return <CheckCircle className="h-4 w-4 text-green-500" />
    return <XCircle className="h-4 w-4 text-red-500" />
  }

  const getValidationBadge = () => {
    if (isValid === null) return null
    
    if (isValid) {
      return (
        <Badge variant="default" className="bg-green-100 text-green-800 border-green-200 text-xs">
          Valid
        </Badge>
      )
    }
    
    return (
      <Badge variant="destructive" className="text-xs">
        Invalid
      </Badge>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label htmlFor={`input-${type}`}>{label}</Label>
        {getValidationBadge()}
      </div>
      
      <div className="relative">
        <Input
          id={`input-${type}`}
          type="text"
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className={`pr-10 ${
            isValid === false ? 'border-red-500 focus:border-red-500' : 
            isValid === true ? 'border-green-500 focus:border-green-500' : ''
          }`}
          required={required}
        />
        {getValidationIcon() && (
          <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
            {getValidationIcon()}
          </div>
        )}
      </div>

      {validationMessage && (
        <div className={`flex items-center gap-2 text-sm ${
          isValid ? 'text-green-600' : 'text-red-600'
        }`}>
          {isValid ? (
            <CheckCircle className="h-3 w-3" />
          ) : (
            <AlertTriangle className="h-3 w-3" />
          )}
          <span>{validationMessage}</span>
        </div>
      )}

      {helperText && !validationMessage && (
        <p className="text-xs text-muted-foreground">{helperText}</p>
      )}
    </div>
  )
}