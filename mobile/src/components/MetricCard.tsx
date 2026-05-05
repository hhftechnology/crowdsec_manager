import type { ComponentType } from 'react';
import { cn } from '@/lib/utils';

type MetricVariant = 'default' | 'success' | 'warning' | 'destructive';

type BorderVariant = 'success' | 'warning' | 'destructive';

const variantClasses: Record<MetricVariant, string> = {
  default: 'text-ink',
  success: 'text-success',
  warning: 'text-warning',
  destructive: 'text-error',
};

const borderVariantClasses: Record<BorderVariant, string> = {
  success: 'border-l-4 border-l-success',
  warning: 'border-l-4 border-l-warning',
  destructive: 'border-l-4 border-l-error',
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
    <div className={cn('rounded-lg border border-hairline bg-surface-card p-sm', borderVariant && borderVariantClasses[borderVariant], className)}>
      <div className="flex items-center gap-xs text-caption text-muted">
        {Icon && <Icon className="h-3.5 w-3.5" />}
        {label}
      </div>
      <div className={cn('mt-xxs font-display text-title-lg tabular-nums', variantClasses[variant])}>
        {value}
      </div>
    </div>
  );
}
