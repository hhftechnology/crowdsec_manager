import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2, Shield, GlobeLock } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';

export default function LoginPage() {
  const navigate = useNavigate();
  const { login, isLoading, error, allowInsecure, setAllowInsecure } = useApi();
  const [url, setUrl] = useState('');

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const ok = await login(url);
    if (ok) {
      navigate('/dashboard');
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-6 bg-background gradient-beige safe-top safe-bottom">
      <div className="w-full max-w-sm animate-slide-up">
        <div className="flex flex-col items-center mb-8">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl gradient-maroon mb-4 shadow-lg">
            <Shield className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">CrowdSec Manager</h1>
          <p className="text-sm text-muted-foreground mt-1">Connect to your API server</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            type="url"
            placeholder={allowInsecure ? 'http://192.168.1.10:8080' : 'https://your-server.example'}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="h-12 rounded-lg bg-card"
            required
          />

          <div className="rounded-lg border border-border bg-card p-3 flex items-center justify-between gap-3">
            <div>
              <div className="text-sm font-medium">Insecure/LAN Mode</div>
              <div className="text-xs text-muted-foreground">
                {allowInsecure ? 'HTTP and LAN URLs allowed' : 'HTTPS required'}
              </div>
            </div>
            <Switch checked={allowInsecure} onCheckedChange={setAllowInsecure} />
          </div>

          {error && <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>}

          <Button type="submit" disabled={isLoading || !url.trim()} className="w-full h-12 rounded-lg text-base font-semibold">
            {isLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : 'Connect'}
          </Button>
        </form>

        <p className="text-center text-xs text-muted-foreground mt-6 flex items-center justify-center gap-1">
          <GlobeLock className="h-3.5 w-3.5" />
          Native build supports direct API URLs without hosting the frontend.
        </p>
      </div>
    </div>
  );
}
