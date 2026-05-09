import type { LucideIcon } from 'lucide-react';
import { Inbox } from 'lucide-react';
import { Button } from '@/components/ui/button';

type EmptyStateCardProps = {
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  icon?: LucideIcon;
};

export function EmptyStateCard({
  title,
  description,
  actionLabel,
  onAction,
  icon: Icon = Inbox,
}: EmptyStateCardProps) {
  return (
    <div className="rounded-lg border border-hairline bg-surface-card p-lg text-center space-y-sm">
      <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-pill bg-canvas">
        <Icon className="h-5 w-5 text-muted" />
      </div>
      <div>
        <h3 className="text-title-sm font-semibold text-ink">{title}</h3>
        <p className="text-body-sm text-muted mt-xxs">{description}</p>
      </div>
      {actionLabel && onAction && (
        <Button variant="secondary" size="sm" onClick={onAction}>
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
