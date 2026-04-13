import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Link2Off, Moon, Sun, Monitor, ChevronRight, Info } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { useTheme } from '@/contexts/ThemeContext';
import { ConnectionProfileForm } from '@/components/ConnectionProfileForm';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import {
  createDefaultConnectionProfileDraft,
  isConnectionDraftComplete,
  normalizeConnectionProfileDraft,
  type ConnectionProfileDraft,
} from '@/lib/connection';

const themeOptions = [
  { value: 'light' as const, icon: Sun, label: 'Light' },
  { value: 'dark' as const, icon: Moon, label: 'Dark' },
  { value: 'system' as const, icon: Monitor, label: 'System' },
];

function buildDraft(profile: ReturnType<typeof useApi>['connectionProfile']): ConnectionProfileDraft {
  return normalizeConnectionProfileDraft(profile ?? createDefaultConnectionProfileDraft());
}

export default function MorePage() {
  const navigate = useNavigate();
  const { theme, setTheme } = useTheme();
  const { connectionProfile, login, logout, isLoading } = useApi();
  const [draft, setDraft] = useState<ConnectionProfileDraft>(() => buildDraft(connectionProfile));

  useEffect(() => {
    setDraft(buildDraft(connectionProfile));
  }, [connectionProfile]);

  const reconnect = async () => {
    if (!isConnectionDraftComplete(draft)) return;

    try {
      const ok = await login(draft);
      if (ok) {
        showActionSuccess('Connected', normalizeConnectionProfileDraft(draft).baseUrl);
      }
    } catch (err) {
      showActionError('Failed to connect', err);
    }
  };

  return (
    <div className="pb-nav">
      <PageHeader title="Settings" subtitle="Connection, proxy access, and theme" />

      <div className="px-4 space-y-4">
        <section className="rounded-xl border border-border bg-card p-4 space-y-4">
          <div>
            <h3 className="text-sm font-semibold">API Connection</h3>
            <p className="text-xs text-muted-foreground mt-1">Update the saved connection profile used for API requests and terminal websockets.</p>
          </div>

          <ConnectionProfileForm value={draft} onChange={setDraft} disabled={isLoading} />

          <div className="flex gap-2">
            <Button onClick={reconnect} disabled={isLoading || !isConnectionDraftComplete(draft)}>
              Reconnect
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                logout();
                navigate('/');
              }}
            >
              <Link2Off className="h-4 w-4 mr-1" />
              Disconnect
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">Current server: {connectionProfile?.baseUrl || 'Not connected'}</p>
        </section>

        <section className="rounded-xl border border-border bg-card p-4 space-y-3">
          <h3 className="text-sm font-semibold">Appearance</h3>
          <div className="grid grid-cols-3 gap-2">
            {themeOptions.map((option) => (
              <Button
                key={option.value}
                variant={theme === option.value ? 'default' : 'secondary'}
                onClick={() => setTheme(option.value)}
                className="h-auto py-3 flex-col gap-1"
              >
                <option.icon className="h-4 w-4" />
                <span className="text-xs">{option.label}</span>
              </Button>
            ))}
          </div>
        </section>

        <section className="rounded-xl border border-border bg-card p-4">
          <Button
            variant="ghost"
            onClick={() => navigate('/about')}
            className="w-full justify-between h-auto py-3"
          >
            <span className="flex items-center gap-2">
              <Info className="h-4 w-4" />
              About CrowdSec Manager
            </span>
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          </Button>
        </section>
      </div>
    </div>
  );
}
