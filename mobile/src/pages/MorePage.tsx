import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Link2Off, Sun, Moon, Monitor } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { useTheme } from '@/contexts/ThemeContext';
import { ConnectionProfileForm } from '@/components/ConnectionProfileForm';
import { PageHeader } from '@/components/PageHeader';
import { ButtonPrimary, ButtonSecondary, UpperBadge } from '@/components/design';
import { cn } from '@/lib/utils';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import {
  createDefaultConnectionProfileDraft,
  isConnectionDraftComplete,
  normalizeConnectionProfileDraft,
  type ConnectionProfileDraft,
} from '@/lib/connection';

const themeOptions = [
  { value: 'light' as const, label: 'Light', Icon: Sun },
  { value: 'dark' as const, label: 'Dark', Icon: Moon },
  { value: 'system' as const, label: 'System', Icon: Monitor },
];

const STORAGE_KEY = 'csm_onboarding_complete';

function buildDraft(
  profile: ReturnType<typeof useApi>['connectionProfile'],
): ConnectionProfileDraft {
  return normalizeConnectionProfileDraft(profile ?? createDefaultConnectionProfileDraft());
}

export default function MorePage() {
  const navigate = useNavigate();
  const { theme, setTheme } = useTheme();
  const { connectionProfile, login, logout, isLoading } = useApi();
  const [draft, setDraft] = useState<ConnectionProfileDraft>(() => buildDraft(connectionProfile));

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

  const replayOnboarding = () => {
    localStorage.removeItem(STORAGE_KEY);
    navigate('/');
    window.location.reload();
  };

  return (
    <div className="pb-nav bg-canvas">
      <PageHeader
        eyebrow="Settings"
        title="A literary control panel."
        subtitle="Connection, theme, and the small print."
      />

      <div className="px-md pb-md space-y-md">
        <section className="rounded-lg bg-surface-card p-md space-y-sm">
          <div className="font-display text-title-md text-ink">API connection</div>
          <p className="text-caption text-muted">
            Update the saved profile used for API and terminal WebSocket calls.
          </p>
          <div className="rounded-md bg-canvas border border-hairline p-sm font-mono text-body-sm text-ink truncate">
            {connectionProfile?.baseUrl || 'Not connected'}
          </div>
          <ConnectionProfileForm value={draft} onChange={setDraft} disabled={isLoading} />
          <div className="flex gap-xs pt-xs">
            <ButtonPrimary
              size="sm"
              onClick={reconnect}
              disabled={isLoading || !isConnectionDraftComplete(draft)}
            >
              Reconnect
            </ButtonPrimary>
            <ButtonSecondary
              size="sm"
              onClick={() => {
                logout();
                navigate('/');
              }}
            >
              <Link2Off className="mr-1 h-4 w-4" />
              Disconnect
            </ButtonSecondary>
          </div>
        </section>

        <section className="rounded-lg border border-hairline bg-canvas p-md">
          <div className="font-display text-title-md text-ink mb-sm">Appearance</div>
          <div className="grid grid-cols-3 gap-xs">
            {themeOptions.map((option) => {
              const active = theme === option.value;
              return (
                <button
                  key={option.value}
                  onClick={() => setTheme(option.value)}
                  className={cn(
                    'h-16 rounded-md flex flex-col items-center justify-center gap-xxs transition-colors',
                    active ? 'bg-primary text-on-primary' : 'bg-surface-card text-ink hover:bg-surface-cream-strong',
                  )}
                  aria-label={`Set theme: ${option.label}`}
                >
                  <option.Icon className="w-5 h-5" />
                  <span className="text-caption font-medium">{option.label}</span>
                </button>
              );
            })}
          </div>
        </section>

        <button
          onClick={() => navigate('/about')}
          className="w-full rounded-lg bg-surface-dark text-on-dark p-md text-left transition-colors hover:bg-surface-dark-soft"
        >
          <div className="flex items-center justify-between">
            <div className="font-display text-title-md text-on-dark">About</div>
            <span className="text-on-dark-soft">→</span>
          </div>
          <p className="mt-xxs text-caption text-on-dark-soft">CrowdSec Manager · 3.0 · HHF Technology</p>
        </button>

        <section className="rounded-lg bg-primary text-on-primary p-md">
          <UpperBadge tone="cream">Beta</UpperBadge>
          <div className="mt-xs font-display text-display-sm">Replay onboarding</div>
          <p className="mt-xxs text-body-sm opacity-90">Walk through the four-slide tour again.</p>
          <div className="mt-sm">
            <ButtonSecondary size="sm" onClick={replayOnboarding}>
              Start over
            </ButtonSecondary>
          </div>
        </section>
      </div>
    </div>
  );
}
