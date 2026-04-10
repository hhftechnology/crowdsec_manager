import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { GlobeLock, Link2Off, Moon, Sun, Monitor, ChevronRight, Info } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { useTheme } from '@/contexts/ThemeContext';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { showActionError, showActionSuccess } from '@/lib/actionToast';

const themeOptions = [
  { value: 'light' as const, icon: Sun, label: 'Light' },
  { value: 'dark' as const, icon: Moon, label: 'Dark' },
  { value: 'system' as const, icon: Monitor, label: 'System' },
];

export default function MorePage() {
  const navigate = useNavigate();
  const { theme, setTheme } = useTheme();
  const { baseUrl, login, logout, allowInsecure, setAllowInsecure, isLoading } = useApi();

  const [serverUrl, setServerUrl] = useState(baseUrl);

  const reconnect = async () => {
    if (!serverUrl.trim()) return;

    try {
      const ok = await login(serverUrl.trim());
      if (ok) {
        showActionSuccess('Connected', serverUrl.trim());
      }
    } catch (err) {
      showActionError('Failed to connect', err);
    }
  };

  return (
    <div className="pb-nav">
      <PageHeader title="Settings" subtitle="Connection, security mode, and theme" />

      <div className="px-4 space-y-4">
        <section className="rounded-xl border border-border bg-card p-4 space-y-3">
          <h3 className="text-sm font-semibold">API Connection</h3>
          <Input
            type="url"
            placeholder="https://your-server.example"
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
          />
          <div className="flex gap-2">
            <Button onClick={reconnect} disabled={isLoading || !serverUrl.trim()}>
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
          <p className="text-xs text-muted-foreground">Current server: {baseUrl || 'Not connected'}</p>
        </section>

        <section className="rounded-xl border border-border bg-card p-4 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold">Insecure/LAN Mode</h3>
              <p className="text-xs text-muted-foreground">
                Off = HTTPS required. On = allow HTTP/LAN hosts for trusted private networks.
              </p>
            </div>
            <Switch checked={allowInsecure} onCheckedChange={setAllowInsecure} />
          </div>
          <div className="text-xs text-muted-foreground flex items-center gap-2">
            <GlobeLock className="h-3.5 w-3.5" />
            {allowInsecure ? 'Insecure mode enabled' : 'Secure mode enabled'}
          </div>
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
