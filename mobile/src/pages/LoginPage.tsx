import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { ConnectionProfileForm } from '@/components/ConnectionProfileForm';
import { ButtonPrimary, Spike, UpperBadge, Wordmark } from '@/components/design';
import {
  createDefaultConnectionProfileDraft,
  isConnectionDraftComplete,
  parseStoredConnectionProfile,
  type ConnectionProfileDraft,
} from '@/lib/connection';

const CONNECTION_PROFILE_KEY = 'csm_connection_profile';

export default function LoginPage() {
  const navigate = useNavigate();
  const { login, isLoading, error } = useApi();
  const [profile, setProfile] = useState<ConnectionProfileDraft>(
    () =>
      parseStoredConnectionProfile(localStorage.getItem(CONNECTION_PROFILE_KEY)) ??
      createDefaultConnectionProfileDraft(),
  );

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const ok = await login(profile);
    if (ok) navigate('/dashboard');
  };

  return (
    <div className="bg-canvas safe-top safe-bottom flex min-h-screen flex-col">
      <div className="px-md pt-md flex items-center justify-between">
        <Wordmark />
        <UpperBadge tone="cream">v2.4</UpperBadge>
      </div>

      <div className="flex-1 px-md pt-xl overflow-y-auto pb-xl">
        <p className="text-caption-uppercase uppercase text-muted font-medium mb-sm">Connect</p>
        <h1 className="font-display text-display-lg text-ink">
          Your CrowdSec, in your pocket.
        </h1>
        <p className="mt-md text-body-md text-body">
          Direct, reverse-proxy, or Pangolin — connect once and everything reads back through the same warm shell.
        </p>

        <form onSubmit={handleSubmit} className="mt-xl">
          <div className="rounded-lg border border-hairline bg-canvas p-md">
            <ConnectionProfileForm value={profile} onChange={setProfile} disabled={isLoading} />
          </div>

          {error && (
            <div className="mt-md rounded-md border border-error/30 bg-error/10 p-sm text-body-sm text-error">
              {error}
            </div>
          )}

          <div className="mt-md">
            <ButtonPrimary
              type="submit"
              full
              size="lg"
              disabled={isLoading || !isConnectionDraftComplete(profile)}
            >
              {isLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : 'Connect'}
            </ButtonPrimary>
          </div>
        </form>

        <div className="mt-lg flex items-center gap-xs text-body-sm text-muted">
          <Spike className="w-3 h-3" />
          Cleartext + LAN allowed via Capacitor — supports proxy auth and Pangolin tokens.
        </div>
      </div>
    </div>
  );
}
