import type { ComponentType } from 'react';
import { cn } from '@/lib/utils';
import { StatusDot, type StatusDotColor } from './StatusDot';

interface StatusRowProps {
  label: string;
  value: React.ReactNode;
  icon?: ComponentType<{ className?: string }>;
  status?: StatusDotColor;
  className?: string;
  mono?: boolean;
}

export function StatusRow({ label, value, icon: Icon, status, className, mono }: StatusRowProps) {
  return (
    <div className={cn('flex items-center justify-between gap-2 py-1.5', className)}>
      <div className="flex items-center gap-2 text-xs text-muted-foreground min-w-0">
        {Icon && <Icon className="h-3.5 w-3.5 shrink-0" />}
        {status && <StatusDot color={status} />}
        <span className="truncate">{label}</span>
      </div>
      <div className={cn('text-xs font-medium text-right truncate max-w-[55%]', mono && 'font-mono')}>
        {value}
      </div>
    </div>
  );
}
