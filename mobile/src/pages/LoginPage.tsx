import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2, Shield, GlobeLock } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { ConnectionProfileForm } from '@/components/ConnectionProfileForm';
import { Button } from '@/components/ui/button';
import {
  createDefaultConnectionProfileDraft,
  isConnectionDraftComplete,
  type ConnectionProfileDraft,
} from '@/lib/connection';

export default function LoginPage() {
  const navigate = useNavigate();
  const { login, isLoading, error } = useApi();
  const [profile, setProfile] = useState<ConnectionProfileDraft>(createDefaultConnectionProfileDraft);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const ok = await login(profile);
    if (ok) {
      navigate('/dashboard');
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-6 py-10 bg-background gradient-beige safe-top safe-bottom">
      <div className="w-full max-w-sm animate-slide-up">
        <div className="flex flex-col items-center mb-8">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl gradient-maroon mb-4 shadow-lg">
            <Shield className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">CrowdSec Manager</h1>
          <p className="text-sm text-muted-foreground mt-1 text-center">Connect directly, through a protected reverse proxy, or through Pangolin.</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <ConnectionProfileForm value={profile} onChange={setProfile} disabled={isLoading} />

          {error && <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>}

          <Button type="submit" disabled={isLoading || !isConnectionDraftComplete(profile)} className="w-full h-12 rounded-lg text-base font-semibold">
            {isLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : 'Connect'}
          </Button>
        </form>

        <p className="text-center text-xs text-muted-foreground mt-6 flex items-center justify-center gap-1">
          <GlobeLock className="h-3.5 w-3.5" />
          Mobile connections support direct URLs, proxy auth, and Pangolin session bootstrap.
        </p>
      </div>
    </div>
  );
}
