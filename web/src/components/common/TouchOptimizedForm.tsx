import React from 'react'
import { cn } from '@/lib/utils'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface TouchOptimizedFormProps {
  children: React.ReactNode
  title?: string
  description?: string
  className?: string
  onSubmit?: (e: React.FormEvent) => void
}

export function TouchOptimizedForm({ 
  children, 
  title, 
  description, 
  className, 
  onSubmit 
}: TouchOptimizedFormProps) {
  const { isMobile, needsTouchOptimization } = useBreakpoints()

  return (
    <Card className={cn("w-full", className)}>
      {(title || description) && (
        <CardHeader className={isMobile ? "p-4" : "p-6"}>
          {title && (
            <CardTitle className={cn(
              isMobile ? "text-lg" : "text-xl"
            )}>
              {title}
            </CardTitle>
          )}
          {description && (
            <p className="text-muted-foreground text-sm mt-2">
              {description}
            </p>
          )}
        </CardHeader>
      )}
      
      <CardContent className={isMobile ? "p-4" : "p-6"}>
        <form 
          onSubmit={onSubmit}
          className={cn(
            "space-y-4",
            needsTouchOptimization && "space-y-6"
          )}
        >
          {children}
        </form>
      </CardContent>
    </Card>
  )
}

interface TouchOptimizedFieldProps {
  label: string
  description?: string
  required?: boolean
  error?: string
  children: React.ReactNode
  className?: string
}

export function TouchOptimizedField({ 
  label, 
  description, 
  required, 
  error, 
  children, 
  className 
}: TouchOptimizedFieldProps) {
  const { isMobile, needsTouchOptimization } = useBreakpoints()

  return (
    <div className={cn("space-y-2", className)}>
      <Label className={cn(
        "text-sm font-medium",
        needsTouchOptimization && "text-base"
      )}>
        {label}
        {required && <span className="text-destructive ml-1">*</span>}
      </Label>
      
      {description && (
        <p className="text-xs text-muted-foreground">
          {description}
        </p>
      )}
      
      <div className={cn(
        needsTouchOptimization && "min-h-[44px] flex items-center"
      )}>
        {children}
      </div>
      
      {error && (
        <p className="text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  )
}

interface TouchOptimizedInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
  description?: string
  error?: string
}

export function TouchOptimizedInput({ 
  label, 
  description, 
  error, 
  className, 
  ...props 
}: TouchOptimizedInputProps) {
  const { needsTouchOptimization } = useBreakpoints()

  const input = (
    <Input
      className={cn(
        needsTouchOptimization && "min-h-[44px] text-base",
        error && "border-destructive",
        className
      )}
      {...props}
    />
  )

  if (label) {
    return (
      <TouchOptimizedField 
        label={label} 
        description={description} 
        error={error}
        required={props.required}
      >
        {input}
      </TouchOptimizedField>
    )
  }

  return input
}

interface TouchOptimizedTextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
  description?: string
  error?: string
}

export function TouchOptimizedTextarea({ 
  label, 
  description, 
  error, 
  className, 
  ...props 
}: TouchOptimizedTextareaProps) {
  const { needsTouchOptimization } = useBreakpoints()

  const textarea = (
    <Textarea
      className={cn(
        needsTouchOptimization && "min-h-[88px] text-base",
        error && "border-destructive",
        className
      )}
      {...props}
    />
  )

  if (label) {
    return (
      <TouchOptimizedField 
        label={label} 
        description={description} 
        error={error}
        required={props.required}
      >
        {textarea}
      </TouchOptimizedField>
    )
  }

  return textarea
}

interface TouchOptimizedSelectProps {
  label?: string
  description?: string
  error?: string
  placeholder?: string
  value?: string
  onValueChange?: (value: string) => void
  children: React.ReactNode
  className?: string
}

export function TouchOptimizedSelect({ 
  label, 
  description, 
  error, 
  placeholder,
  value,
  onValueChange,
  children,
  className
}: TouchOptimizedSelectProps) {
  const { needsTouchOptimization } = useBreakpoints()

  const select = (
    <Select value={value} onValueChange={onValueChange}>
      <SelectTrigger className={cn(
        needsTouchOptimization && "min-h-[44px] text-base",
        error && "border-destructive",
        className
      )}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {children}
      </SelectContent>
    </Select>
  )

  if (label) {
    return (
      <TouchOptimizedField 
        label={label} 
        description={description} 
        error={error}
      >
        {select}
      </TouchOptimizedField>
    )
  }

  return select
}

interface TouchOptimizedCheckboxProps {
  label: string
  description?: string
  checked?: boolean
  onCheckedChange?: (checked: boolean) => void
  className?: string
}

export function TouchOptimizedCheckbox({ 
  label, 
  description, 
  checked, 
  onCheckedChange,
  className
}: TouchOptimizedCheckboxProps) {
  const { needsTouchOptimization } = useBreakpoints()

  return (
    <div className={cn(
      "flex items-start space-x-3",
      needsTouchOptimization && "min-h-[44px] py-2",
      className
    )}>
      <Checkbox
        checked={checked}
        onCheckedChange={onCheckedChange}
        className={needsTouchOptimization ? "mt-1" : "mt-0.5"}
      />
      <div className="flex-1 min-w-0">
        <Label className={cn(
          "text-sm font-medium cursor-pointer",
          needsTouchOptimization && "text-base"
        )}>
          {label}
        </Label>
        {description && (
          <p className="text-xs text-muted-foreground mt-1">
            {description}
          </p>
        )}
      </div>
    </div>
  )
}

interface TouchOptimizedSwitchProps {
  label: string
  description?: string
  checked?: boolean
  onCheckedChange?: (checked: boolean) => void
  className?: string
}

export function TouchOptimizedSwitch({ 
  label, 
  description, 
  checked, 
  onCheckedChange,
  className
}: TouchOptimizedSwitchProps) {
  const { needsTouchOptimization } = useBreakpoints()

  return (
    <div className={cn(
      "flex items-center justify-between",
      needsTouchOptimization && "min-h-[44px] py-2",
      className
    )}>
      <div className="flex-1 min-w-0 mr-4">
        <Label className={cn(
          "text-sm font-medium",
          needsTouchOptimization && "text-base"
        )}>
          {label}
        </Label>
        {description && (
          <p className="text-xs text-muted-foreground mt-1">
            {description}
          </p>
        )}
      </div>
      <Switch
        checked={checked}
        onCheckedChange={onCheckedChange}
      />
    </div>
  )
}

interface TouchOptimizedButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link'
  size?: 'default' | 'sm' | 'lg' | 'icon'
  fullWidth?: boolean
  loading?: boolean
  loadingText?: string
}

export function TouchOptimizedButton({ 
  variant = 'default',
  size = 'default',
  fullWidth = false,
  loading = false,
  loadingText,
  className,
  children,
  ...props
}: TouchOptimizedButtonProps) {
  const { needsTouchOptimization } = useBreakpoints()

  return (
    <Button
      variant={variant}
      size={needsTouchOptimization ? 'lg' : size}
      className={cn(
        needsTouchOptimization && "min-h-[44px] text-base",
        fullWidth && "w-full",
        className
      )}
      disabled={loading || props.disabled}
      {...props}
    >
      {loading && (
        <svg
          className="mr-2 h-4 w-4 animate-spin"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="m4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      )}
      {loading ? (loadingText || "Loading...") : children}
    </Button>
  )
}

export default TouchOptimizedForm