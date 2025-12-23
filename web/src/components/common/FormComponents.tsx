import { ReactNode, useState } from "react"
import { UseFormReturn, FieldPath, FieldValues } from "react-hook-form"
import { AlertCircle, Check, Eye, EyeOff } from "lucide-react"
import { cn } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Switch } from "@/components/ui/switch"
import {
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue, 
} from "@/components/ui/select"
import {
  FormField, 
  FormItem, 
  FormLabel, 
  FormControl, 
  FormDescription, 
  FormMessage, 
  Form, 
} from "@/components/ui/form"

export interface FormFieldProps<T extends FieldValues> {
  form: UseFormReturn<T>
  name: FieldPath<T>
  label?: string
  description?: string
  placeholder?: string
  disabled?: boolean
  className?: string
}

export interface TextFieldProps<T extends FieldValues> extends FormFieldProps<T> {
  type?: 'text' | 'email' | 'password' | 'url' | 'tel'
  showPasswordToggle?: boolean
}

export function TextField<T extends FieldValues>({
  form, 
  name, 
  label, 
  description, 
  placeholder, 
  type = 'text', 
  showPasswordToggle = false, 
  disabled = false, 
  className
}: TextFieldProps<T>) {
  const [showPassword, setShowPassword] = useState(false)
  const inputType = type === 'password' && showPassword ? 'text' : type

  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field, fieldState }) => (
        <FormItem className={className}>
          {label && <FormLabel>{label}</FormLabel>}
          <FormControl>
            <div className="relative">
              <Input
                {...field}
                type={inputType}
                placeholder={placeholder}
                disabled={disabled}
                className={cn(
                  fieldState.error && "border-red-500 focus-visible:ring-red-500", 
                  showPasswordToggle && "pr-10"
                )}
              />
              {showPasswordToggle && type === 'password' && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={disabled}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4 text-muted-foreground" />
                  ) : (
                    <Eye className="h-4 w-4 text-muted-foreground" />
                  )}
                </Button>
              )}
            </div>
          </FormControl>
          {description && <FormDescription>{description}</FormDescription>}
          <FormMessage />
        </FormItem>
      )}
    />
  )
}

export interface TextAreaFieldProps<T extends FieldValues> extends FormFieldProps<T> {
  rows?: number
}

export function TextAreaField<T extends FieldValues>({
  form, 
  name, 
  label, 
  description, 
  placeholder, 
  rows = 3, 
  disabled = false, 
  className
}: TextAreaFieldProps<T>) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field, fieldState }) => (
        <FormItem className={className}>
          {label && <FormLabel>{label}</FormLabel>}
          <FormControl>
            <Textarea
              {...field}
              placeholder={placeholder}
              disabled={disabled}
              rows={rows}
              className={cn(
                fieldState.error && "border-red-500 focus-visible:ring-red-500"
              )}
            />
          </FormControl>
          {description && <FormDescription>{description}</FormDescription>}
          <FormMessage />
        </FormItem>
      )}
    />
  )
}

export interface SelectFieldProps<T extends FieldValues> extends FormFieldProps<T> {
  options: Array<{ value: string; label: string; disabled?: boolean }>
}

export function SelectField<T extends FieldValues>({
  form, 
  name, 
  label, 
  description, 
  placeholder = "Select an option...", 
  options, 
  disabled = false, 
  className
}: SelectFieldProps<T>) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field, fieldState }) => (
        <FormItem className={className}>
          {label && <FormLabel>{label}</FormLabel>}
          <Select
            onValueChange={field.onChange}
            defaultValue={field.value}
            disabled={disabled}
          >
            <FormControl>
              <SelectTrigger
                className={cn(
                  fieldState.error && "border-red-500 focus:ring-red-500"
                )}
              >
                <SelectValue placeholder={placeholder} />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              {options.map((option) => (
                <SelectItem
                  key={option.value}
                  value={option.value}
                  disabled={option.disabled}
                >
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {description && <FormDescription>{description}</FormDescription>}
          <FormMessage />
        </FormItem>
      )}
    />
  )
}

export interface CheckboxFieldProps<T extends FieldValues> extends FormFieldProps<T> {
  
}

export function CheckboxField<T extends FieldValues>({
  form, 
  name, 
  label, 
  description, 
  disabled = false, 
  className
}: CheckboxFieldProps<T>) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem className={cn("flex flex-row items-start space-x-3 space-y-0", className)}>
          <FormControl>
            <Checkbox
              checked={field.value}
              onCheckedChange={field.onChange}
              disabled={disabled}
            />
          </FormControl>
          <div className="space-y-1 leading-none">
            {label && <FormLabel>{label}</FormLabel>}
            {description && <FormDescription>{description}</FormDescription>}
          </div>
        </FormItem>
      )}
    />
  )
}

export interface SwitchFieldProps<T extends FieldValues> extends FormFieldProps<T> {
  
}

export function SwitchField<T extends FieldValues>({
  form, 
  name, 
  label, 
  description, 
  disabled = false, 
  className
}: SwitchFieldProps<T>) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem className={cn("flex flex-row items-center justify-between rounded-lg border p-4", className)}>
          <div className="space-y-0.5">
            {label && <FormLabel className="text-base">{label}</FormLabel>}
            {description && <FormDescription>{description}</FormDescription>}
          </div>
          <FormControl>
            <Switch
              checked={field.value}
              onCheckedChange={field.onChange}
              disabled={disabled}
            />
          </FormControl>
        </FormItem>
      )}
    />
  )
}

export interface FormActionsProps {
  loading?: boolean
  submitText?: string
  cancelText?: string
  onCancel?: () => void
  showCancel?: boolean
  className?: string
}

export function FormActions({
  loading = false, 
  submitText = "Submit", 
  cancelText = "Cancel", 
  onCancel, 
  showCancel = true, 
  className
}: FormActionsProps) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      {showCancel && onCancel && (
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={loading}
        >
          {cancelText}
        </Button>
      )}
      <Button type="submit" disabled={loading}>
        {loading && <div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />}
        {submitText}
      </Button>
    </div>
  )
}

export interface ValidationMessageProps {
  type: 'error' | 'success' | 'warning' | 'info'
  message: string
  className?: string
}

export function ValidationMessage({ type, message, className }: ValidationMessageProps) {
  const styles = {
    error: "text-red-600 bg-red-50 border-red-200 dark:text-red-400 dark:bg-red-950/50 dark:border-red-800", 
    success: "text-green-600 bg-green-50 border-green-200 dark:text-green-400 dark:bg-green-950/50 dark:border-green-800", 
    warning: "text-yellow-600 bg-yellow-50 border-yellow-200 dark:text-yellow-400 dark:bg-yellow-950/50 dark:border-yellow-800", 
    info: "text-blue-600 bg-blue-50 border-blue-200 dark:text-blue-400 dark:bg-blue-950/50 dark:border-blue-800"
  }

  const icons = {
    error: AlertCircle, 
    success: Check, 
    warning: AlertCircle, 
    info: AlertCircle
  }

  const Icon = icons[type]

  return (
    <div className={cn(
      "flex items-center gap-2 rounded-md border p-3 text-sm", 
      styles[type], 
      className
    )}>
      <Icon className="h-4 w-4 flex-shrink-0" />
      <span>{message}</span>
    </div>
  )
}

export interface FormSectionProps {
  title?: string
  description?: string
  children: ReactNode
  className?: string
}

export function FormSection({ title, description, children, className }: FormSectionProps) {
  return (
    <div className={cn("space-y-4", className)}>
      {(title || description) && (
        <div className="space-y-1">
          {title && <h3 className="text-lg font-medium">{title}</h3>}
          {description && <p className="text-sm text-muted-foreground">{description}</p>}
        </div>
      )}
      <div className="space-y-4">
        {children}
      </div>
    </div>
  )
}

// Preset form components for common patterns
export const FormComponents = {
  TextField, 
  TextAreaField, 
  SelectField, 
  CheckboxField, 
  SwitchField, 
  FormActions, 
  ValidationMessage, 
  FormSection, 
  Form
}