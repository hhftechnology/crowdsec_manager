import { Badge } from '@/components/ui/badge';

interface AlertEntry {
  id?: number;
  scenario?: string;
  value?: string;
  start_at?: string;
  events_count?: number;
  source?: { ip?: string; cn?: string };
}

interface RecentActivityPanelProps {
  alerts: AlertEntry[];
}

function relativeTime(dateStr?: string): string {
  if (!dateStr) return '';
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffSec = Math.floor((now - then) / 1000);

  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

export function RecentActivityPanel({ alerts }: RecentActivityPanelProps) {
  const recent = alerts.slice(0, 5);

  if (recent.length === 0) return null;

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-3">
      <h3 className="text-sm font-semibold">Recent Activity</h3>

      <div className="space-y-2">
        {recent.map((alert, index) => (
          <div
            key={alert.id ?? index}
            className="flex items-start gap-3 py-1.5 border-b border-border last:border-b-0"
          >
            <div className="mt-1.5 h-1.5 w-1.5 rounded-full bg-primary shrink-0" />
            <div className="min-w-0 flex-1 space-y-0.5">
              <div className="text-xs font-medium truncate">
                {alert.scenario || 'Unknown scenario'}
              </div>
              <div className="flex items-center gap-2">
                {alert.source?.ip && (
                  <span className="text-[10px] font-mono text-muted-foreground">
                    {alert.source.ip}
                  </span>
                )}
                {alert.start_at && (
                  <span className="text-[10px] text-muted-foreground">
                    {relativeTime(alert.start_at)}
                  </span>
                )}
              </div>
            </div>
            {alert.events_count != null && (
              <Badge variant="secondary" className="text-[10px] shrink-0">
                {alert.events_count} evt{alert.events_count !== 1 ? 's' : ''}
              </Badge>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
