import { useRef, useState } from 'react';
import { CloudOff, WifiOff } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { useMountEffect } from '@/hooks/useMountEffect';

export function OfflineConnectionBanner() {
  const { api, connectionProfile, isAuthenticated } = useApi();
  const [isOnline, setIsOnline] = useState(() => navigator.onLine);
  const [apiReachable, setApiReachable] = useState(true);

  const apiRef = useRef(api);
  const baseUrlRef = useRef(connectionProfile?.baseUrl ?? '');
  const isAuthRef = useRef(isAuthenticated);
  const isOnlineRef = useRef(isOnline);
  apiRef.current = api;
  baseUrlRef.current = connectionProfile?.baseUrl ?? '';
  isAuthRef.current = isAuthenticated;
  isOnlineRef.current = isOnline;

  useMountEffect(() => {
    const onOnline = () => setIsOnline(true);
    const onOffline = () => setIsOnline(false);
    window.addEventListener('online', onOnline);
    window.addEventListener('offline', onOffline);

    const checkReachability = async () => {
      if (!isAuthRef.current || !apiRef.current || !isOnlineRef.current) {
        setApiReachable(true);
        return;
      }

      try {
        await apiRef.current.health.getStack();
        setApiReachable(true);
      } catch {
        setApiReachable(false);
      }
    };

    void checkReachability();
    const interval = window.setInterval(() => {
      void checkReachability();
    }, 15000);

    return () => {
      window.removeEventListener('online', onOnline);
      window.removeEventListener('offline', onOffline);
      window.clearInterval(interval);
    };
  });

  if (!isOnline) {
    return (
      <div className="sticky top-0 z-50 border-b border-warning/30 bg-warning/10 px-4 py-2 text-xs text-warning-foreground flex items-center gap-2">
        <WifiOff className="h-3.5 w-3.5" />
        You are offline. Some actions may fail until connection is restored.
      </div>
    );
  }

  if (isAuthenticated && !apiReachable) {
    return (
      <div className="sticky top-0 z-50 border-b border-destructive/30 bg-destructive/10 px-4 py-2 text-xs text-destructive flex items-center gap-2">
        <CloudOff className="h-3.5 w-3.5" />
        API unreachable at {baseUrlRef.current}. Check server status or network path.
      </div>
    );
  }

  return null;
}
