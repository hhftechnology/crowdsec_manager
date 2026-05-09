import { Trash2, Eye } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { StatusDot } from '@/components/StatusDot';
import { relativeTime } from '@/lib/utils';
import type { CrowdsecAlert } from '@/lib/api';

interface AlertsListPanelProps {
  alerts: CrowdsecAlert[];
  onDelete: (id: number) => void;
  onInspect: (id: number) => void;
}

export function AlertsListPanel({ alerts, onDelete, onInspect }: AlertsListPanelProps) {
  if (alerts.length === 0) {
    return (
      <div className="rounded-lg border border-hairline bg-surface-card p-md">
        <h3 className="text-title-sm font-semibold mb-xs">Recent Alerts</h3>
        <p className="text-caption text-muted">No recent alerts.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-hairline bg-surface-card p-md space-y-xs">
      <div className="flex items-center justify-between">
        <h3 className="text-title-sm font-semibold text-ink">Recent Alerts</h3>
        <Badge variant="outline">{alerts.length}</Badge>
      </div>
      <div className="max-h-[60vh] overflow-y-auto">
        <div className="space-y-xs">
          {alerts.map((alert, i) => (
            <div
              key={alert.id || i}
              className="rounded-lg border border-hairline-soft bg-canvas p-sm space-y-xxs"
            >
              <div className="flex items-center justify-between gap-xs">
                <div className="flex items-center gap-xs min-w-0">
                  <StatusDot color="warning" />
                  <span className="text-caption font-medium truncate">
                    {alert.scenario || 'Alert'}
                  </span>
                </div>
                <div className="flex items-center gap-xxs shrink-0">
                  {alert.events_count !== undefined && (
                    <Badge variant="secondary" className="text-caption">
                      {alert.events_count} events
                    </Badge>
                  )}
                  {alert.id && (
                    <Badge variant="outline" className="text-caption">
                      #{alert.id}
                    </Badge>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-xs text-caption text-muted">
                {alert.source?.ip && (
                  <span className="font-mono">{alert.source.ip}</span>
                )}
                {alert.source?.cn && (
                  <>
                    <span>·</span>
                    <span>{alert.source.cn}</span>
                  </>
                )}
                {alert.start_at && (
                  <>
                    <span>·</span>
                    <span>{relativeTime(alert.start_at)}</span>
                  </>
                )}
              </div>

              <div className="flex items-center justify-end gap-xxs pt-xxs">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-xs text-caption"
                  onClick={() => alert.id && onInspect(alert.id)}
                >
                  <Eye className="h-3 w-3 mr-xxs" />
                  Inspect
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-xs text-caption text-error hover:text-error"
                  onClick={() => alert.id && onDelete(alert.id)}
                >
                  <Trash2 className="h-3 w-3 mr-xxs" />
                  Delete
                </Button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
