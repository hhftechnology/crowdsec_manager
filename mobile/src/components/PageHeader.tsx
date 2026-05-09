import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { Spike } from '@/components/design';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  eyebrow?: string;
  action?: ReactNode;
  dark?: boolean;
  className?: string;
}

export function PageHeader({ title, subtitle, eyebrow, action, dark = false, className }: PageHeaderProps) {
  return (
    <header
      className={cn(
        'px-md pt-lg pb-md',
        dark ? 'bg-surface-dark text-on-dark' : 'bg-canvas text-ink',
        className,
      )}
    >
      <div className="flex items-start justify-between gap-md">
        <div className="min-w-0 flex-1">
          {eyebrow && (
            <div className="flex items-center gap-xs mb-xs">
              <Spike className={cn('w-3 h-3', dark ? 'text-on-dark' : 'text-ink')} />
              <span
                className={cn(
                  'text-caption-uppercase uppercase font-medium',
                  dark ? 'text-on-dark-soft' : 'text-muted',
                )}
              >
                {eyebrow}
              </span>
            </div>
          )}
          <h1 className={cn('font-display text-display-md', dark ? 'text-on-dark' : 'text-ink')}>{title}</h1>
          {subtitle && (
            <p className={cn('mt-xxs text-body-sm', dark ? 'text-on-dark-soft' : 'text-muted')}>{subtitle}</p>
          )}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
    </header>
  );
}
