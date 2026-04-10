import { useRef, useState } from 'react';
import { CloudOff, WifiOff } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { useMountEffect } from '@/hooks/useMountEffect';

export function OfflineConnectionBanner() {
  const { baseUrl, isAuthenticated } = useApi();
  const [isOnline, setIsOnline] = useState(() => navigator.onLine);
  const [apiReachable, setApiReachable] = useState(true);

  // Refs to avoid stale closures in the interval callback
  const baseUrlRef = useRef(baseUrl);
  const isAuthRef = useRef(isAuthenticated);
  const isOnlineRef = useRef(isOnline);
  baseUrlRef.current = baseUrl;
  isAuthRef.current = isAuthenticated;
  isOnlineRef.current = isOnline;

  useMountEffect(() => {
    // Online/offline listeners
    const onOnline = () => setIsOnline(true);
    const onOffline = () => setIsOnline(false);
    window.addEventListener('online', onOnline);
    window.addEventListener('offline', onOffline);

    // API reachability check
    const controller = new AbortController();
    const checkReachability = async () => {
      if (!isAuthRef.current || !baseUrlRef.current || !isOnlineRef.current) {
        setApiReachable(true);
        return;
      }
      try {
        const response = await fetch(`${baseUrlRef.current}/api/health/stack`, { signal: controller.signal });
        setApiReachable(response.ok);
      } catch {
        setApiReachable(false);
      }
    };
    checkReachability();
    const interval = window.setInterval(checkReachability, 15000);

    return () => {
      window.removeEventListener('online', onOnline);
      window.removeEventListener('offline', onOffline);
      controller.abort();
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
        API unreachable at {baseUrl}. Check server status or network path.
      </div>
    );
  }

  return null;
}
