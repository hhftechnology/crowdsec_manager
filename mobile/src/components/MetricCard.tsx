import type { ComponentType } from 'react';
import { cn } from '@/lib/utils';

type MetricVariant = 'default' | 'success' | 'warning' | 'destructive';

type BorderVariant = 'success' | 'warning' | 'destructive';

const variantClasses: Record<MetricVariant, string> = {
  default: 'text-foreground',
  success: 'text-emerald-600 dark:text-emerald-400',
  warning: 'text-amber-600 dark:text-amber-400',
  destructive: 'text-red-600 dark:text-red-400',
};

const borderVariantClasses: Record<BorderVariant, string> = {
  success: 'border-l-4 border-l-emerald-500',
  warning: 'border-l-4 border-l-amber-500',
  destructive: 'border-l-4 border-l-red-500',
};

interface MetricCardProps {
  label: string;
  value: number | string;
  icon?: ComponentType<{ className?: string }>;
  variant?: MetricVariant;
  borderVariant?: BorderVariant;
  className?: string;
}

export function MetricCard({ label, value, icon: Icon, variant = 'default', borderVariant, className }: MetricCardProps) {
  return (
    <div className={cn('rounded-xl border border-border bg-card p-3', borderVariant && borderVariantClasses[borderVariant], className)}>
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        {Icon && <Icon className="h-3.5 w-3.5" />}
        {label}
      </div>
      <div className={cn('mt-1 text-lg font-bold tabular-nums', variantClasses[variant])}>
        {value}
      </div>
    </div>
  );
}
