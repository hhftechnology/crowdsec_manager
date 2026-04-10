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
      <div className="rounded-xl border border-border bg-card p-4">
        <h3 className="text-sm font-semibold mb-2">Recent Alerts</h3>
        <p className="text-xs text-muted-foreground">No recent alerts.</p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Recent Alerts</h3>
        <Badge variant="outline">{alerts.length}</Badge>
      </div>
      <div className="max-h-[60vh] overflow-y-auto">
        <div className="space-y-2">
          {alerts.map((alert, i) => (
            <div
              key={alert.id || i}
              className="rounded-lg border border-border/50 bg-muted/30 p-3 space-y-1"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <StatusDot color="warning" />
                  <span className="text-xs font-medium truncate">
                    {alert.scenario || 'Alert'}
                  </span>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  {alert.events_count !== undefined && (
                    <Badge variant="secondary" className="text-[10px]">
                      {alert.events_count} events
                    </Badge>
                  )}
                  {alert.id && (
                    <Badge variant="outline" className="text-[10px]">
                      #{alert.id}
                    </Badge>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
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

              <div className="flex items-center justify-end gap-1 pt-1">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-[10px]"
                  onClick={() => alert.id && onInspect(alert.id)}
                >
                  <Eye className="h-3 w-3 mr-1" />
                  Inspect
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-[10px] text-destructive hover:text-destructive"
                  onClick={() => alert.id && onDelete(alert.id)}
                >
                  <Trash2 className="h-3 w-3 mr-1" />
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
