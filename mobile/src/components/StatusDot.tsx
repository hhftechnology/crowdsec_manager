import { cn } from '@/lib/utils';

export type StatusDotColor = 'success' | 'warning' | 'error' | 'default';

const colorMap: Record<StatusDotColor, string> = {
  success: 'bg-emerald-500',
  warning: 'bg-amber-500',
  error: 'bg-red-500',
  default: 'bg-muted-foreground/50',
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
        'inline-block h-2 w-2 rounded-full shrink-0',
        colorMap[color],
        pulse && 'animate-pulse',
        className,
      )}
    />
  );
}
