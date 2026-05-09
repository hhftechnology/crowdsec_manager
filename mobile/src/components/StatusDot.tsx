import { cn } from '@/lib/utils';

export type StatusDotColor = 'success' | 'warning' | 'error' | 'default';

const colorMap: Record<StatusDotColor, string> = {
  success: 'bg-success',
  warning: 'bg-warning',
  error: 'bg-error',
  default: 'bg-muted-soft',
};

interface StatusDotProps {
  color?: StatusDotColor;
  className?: string;
  pulse?: boolean;
}

export function StatusDot({ color = 'default', className, pulse }: StatusDotProps) {
  return (
    <span
      className={cn(
        'inline-block h-2 w-2 rounded-pill shrink-0',
        colorMap[color],
        pulse && 'animate-pulse',
        className,
      )}
    />
  );
}
