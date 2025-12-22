import * as React from "react"
import { toast } from "sonner"
import { 
  CheckCircle, 
  AlertCircle, 
  AlertTriangle, 
  Info, 
  X,
  Bell,
  BellRing
} from "lucide-react"
import { cn } from "@/lib/utils"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

// Toast notification helpers
export const notifications = {
  success: (message: string, description?: string) => {
    toast.success(message, {
      description,
      duration: 4000,
    })
  },
  
  error: (message: string, description?: string) => {
    toast.error(message, {
      description,
      duration: 6000,
    })
  },
  
  warning: (message: string, description?: string) => {
    toast.warning(message, {
      description,
      duration: 5000,
    })
  },
  
  info: (message: string, description?: string) => {
    toast.info(message, {
      description,
      duration: 4000,
    })
  },
  
  loading: (message: string, promise: Promise<any>) => {
    return toast.promise(promise, {
      loading: message,
      success: "Operation completed successfully",
      error: "Operation failed",
    })
  },
  
  custom: (content: React.ReactNode, options?: any) => {
    toast.custom(content, options)
  }
}

// Alert component variants
export interface AlertProps {
  variant?: 'default' | 'destructive' | 'warning' | 'success' | 'info'
  title?: string
  description?: string
  children?: React.ReactNode
  onClose?: () => void
  className?: string
}

const alertVariants = {
  default: {
    container: "",
    icon: Info,
    iconColor: "text-blue-600 dark:text-blue-400"
  },
  destructive: {
    container: "border-red-200 bg-red-50/50 dark:border-red-800 dark:bg-red-950/50",
    icon: AlertCircle,
    iconColor: "text-red-600 dark:text-red-400"
  },
  warning: {
    container: "border-yellow-200 bg-yellow-50/50 dark:border-yellow-800 dark:bg-yellow-950/50",
    icon: AlertTriangle,
    iconColor: "text-yellow-600 dark:text-yellow-400"
  },
  success: {
    container: "border-green-200 bg-green-50/50 dark:border-green-800 dark:bg-green-950/50",
    icon: CheckCircle,
    iconColor: "text-green-600 dark:text-green-400"
  },
  info: {
    container: "border-blue-200 bg-blue-50/50 dark:border-blue-800 dark:bg-blue-950/50",
    icon: Info,
    iconColor: "text-blue-600 dark:text-blue-400"
  }
}

export function AlertNotification({
  variant = 'default',
  title,
  description,
  children,
  onClose,
  className
}: AlertProps) {
  const variantConfig = alertVariants[variant]
  const Icon = variantConfig.icon

  return (
    <Alert className={cn(variantConfig.container, className)}>
      <div className="flex items-start gap-3">
        <Icon className={cn("h-4 w-4 mt-0.5", variantConfig.iconColor)} />
        <div className="flex-1 space-y-1">
          {title && <AlertTitle>{title}</AlertTitle>}
          {description && <AlertDescription>{description}</AlertDescription>}
          {children}
        </div>
        {onClose && (
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0 hover:bg-transparent"
            onClick={onClose}
          >
            <X className="h-3 w-3" />
          </Button>
        )}
      </div>
    </Alert>
  )
}

// Notification banner for persistent messages
export interface NotificationBannerProps {
  variant?: 'info' | 'warning' | 'error' | 'success'
  title?: string
  message: string
  action?: {
    label: string
    onClick: () => void
  }
  onDismiss?: () => void
  className?: string
}

export function NotificationBanner({
  variant = 'info',
  title,
  message,
  action,
  onDismiss,
  className
}: NotificationBannerProps) {
  const variantConfig = alertVariants[variant] || alertVariants.info
  const Icon = variantConfig.icon

  return (
    <div className={cn(
      "flex items-center gap-3 rounded-lg border p-4",
      variantConfig.container,
      className
    )}>
      <Icon className={cn("h-5 w-5 flex-shrink-0", variantConfig.iconColor)} />
      <div className="flex-1 min-w-0">
        {title && (
          <p className="text-sm font-medium text-foreground">{title}</p>
        )}
        <p className="text-sm text-muted-foreground">{message}</p>
      </div>
      <div className="flex items-center gap-2">
        {action && (
          <Button
            variant="outline"
            size="sm"
            onClick={action.onClick}
          >
            {action.label}
          </Button>
        )}
        {onDismiss && (
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0"
            onClick={onDismiss}
          >
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  )
}

// Notification card for more complex notifications
export interface NotificationCardProps {
  title: string
  description?: string
  timestamp?: Date
  read?: boolean
  priority?: 'low' | 'medium' | 'high'
  actions?: Array<{
    label: string
    onClick: () => void
    variant?: 'default' | 'outline' | 'ghost'
  }>
  onMarkAsRead?: () => void
  onDismiss?: () => void
  className?: string
}

export function NotificationCard({
  title,
  description,
  timestamp,
  read = false,
  priority = 'medium',
  actions = [],
  onMarkAsRead,
  onDismiss,
  className
}: NotificationCardProps) {
  const priorityColors = {
    low: "border-l-blue-500",
    medium: "border-l-yellow-500",
    high: "border-l-red-500"
  }

  return (
    <Card className={cn(
      "border-l-4 transition-all duration-200",
      priorityColors[priority],
      !read && "bg-muted/30",
      className
    )}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              {!read && <div className="h-2 w-2 bg-blue-500 rounded-full" />}
              {title}
            </CardTitle>
            {description && (
              <CardDescription className="text-xs">
                {description}
              </CardDescription>
            )}
          </div>
          <div className="flex items-center gap-1">
            {priority === 'high' && (
              <Badge variant="destructive" className="text-xs">
                High
              </Badge>
            )}
            {onDismiss && (
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0"
                onClick={onDismiss}
              >
                <X className="h-3 w-3" />
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      
      {(actions.length > 0 || timestamp || onMarkAsRead) && (
        <CardContent className="pt-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {actions.map((action, index) => (
                <Button
                  key={index}
                  variant={action.variant || 'outline'}
                  size="sm"
                  onClick={action.onClick}
                >
                  {action.label}
                </Button>
              ))}
            </div>
            
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              {timestamp && (
                <span>
                  {timestamp.toLocaleDateString()} {timestamp.toLocaleTimeString()}
                </span>
              )}
              {onMarkAsRead && !read && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-xs"
                  onClick={onMarkAsRead}
                >
                  Mark as read
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  )
}

// Notification center component
export interface NotificationCenterProps {
  notifications: Array<NotificationCardProps & { id: string }>
  onMarkAllAsRead?: () => void
  onClearAll?: () => void
  className?: string
}

export function NotificationCenter({
  notifications: notificationList,
  onMarkAllAsRead,
  onClearAll,
  className
}: NotificationCenterProps) {
  const unreadCount = notificationList.filter(n => !n.read).length

  return (
    <Card className={cn("w-full max-w-md", className)}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <BellRing className="h-4 w-4" />
            Notifications
            {unreadCount > 0 && (
              <Badge variant="secondary" className="text-xs">
                {unreadCount}
              </Badge>
            )}
          </CardTitle>
          <div className="flex items-center gap-1">
            {onMarkAllAsRead && unreadCount > 0 && (
              <Button
                variant="ghost"
                size="sm"
                className="text-xs"
                onClick={onMarkAllAsRead}
              >
                Mark all read
              </Button>
            )}
            {onClearAll && (
              <Button
                variant="ghost"
                size="sm"
                className="text-xs"
                onClick={onClearAll}
              >
                Clear all
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-2 max-h-96 overflow-y-auto">
        {notificationList.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <Bell className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No notifications</p>
          </div>
        ) : (
          notificationList.map((notification) => (
            <NotificationCard
              key={notification.id}
              {...notification}
              className="border-0 shadow-none bg-transparent"
            />
          ))
        )}
      </CardContent>
    </Card>
  )
}

// Preset notification components for common patterns
export const NotificationComponents = {
  notifications,
  AlertNotification,
  NotificationBanner,
  NotificationCard,
  NotificationCenter
}