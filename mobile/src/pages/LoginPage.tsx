import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2, Shield, GlobeLock } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { ConnectionProfileForm } from '@/components/ConnectionProfileForm';
import { Button } from '@/components/ui/button';
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
      parseStoredConnectionProfile(
        localStorage.getItem(CONNECTION_PROFILE_KEY),
      ) ?? createDefaultConnectionProfileDraft(),
  );

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const ok = await login(profile);
    if (ok) {
      navigate('/dashboard');
    }
  };

  return (
    <div className="gradient-beige safe-top safe-bottom flex min-h-screen flex-col items-center justify-center bg-background px-6 py-10">
      <div className="w-full max-w-sm animate-slide-up">
        <div className="mb-8 flex flex-col items-center">
          <div className="gradient-maroon mb-4 flex h-16 w-16 items-center justify-center rounded-2xl shadow-lg">
            <Shield className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">
            CrowdSec Manager
          </h1>
          <p className="mt-1 text-center text-sm text-muted-foreground">
            Connect directly, through a protected reverse proxy, or through
            Pangolin.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <ConnectionProfileForm
            value={profile}
            onChange={setProfile}
            disabled={isLoading}
          />

          {error && (
            <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}

          <Button
            type="submit"
            disabled={isLoading || !isConnectionDraftComplete(profile)}
            className="h-12 w-full rounded-lg text-base font-semibold"
          >
            {isLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : 'Connect'}
          </Button>
        </form>

        <p className="mt-6 flex items-center justify-center gap-1 text-center text-xs text-muted-foreground">
          <GlobeLock className="h-3.5 w-3.5" />
          Mobile connections support direct URLs, proxy auth, and Pangolin
          access tokens.
        </p>
      </div>
    </div>
  );
}
