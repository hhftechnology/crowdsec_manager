import { ArrowRight, Rocket, X } from 'lucide-react';
import { useManagerUpdate } from '@/hooks/useManagerUpdate';

export function ManagerUpdateCard() {
  const { available, latestVersion, installUrl, dismissed, dismiss, currentVersion } =
    useManagerUpdate();

  if (!available || dismissed || !latestVersion || !currentVersion) return null;

  return (
    <div className="relative rounded-lg border border-hairline bg-surface-card p-md text-ink dark:bg-surface-dark dark:text-on-dark">
      <button
        type="button"
        onClick={dismiss}
        aria-label="Dismiss update notification"
        className="absolute right-2 top-2 inline-flex h-7 w-7 items-center justify-center rounded-pill text-muted hover:bg-surface-soft dark:text-on-dark-soft dark:hover:bg-surface-dark-soft"
      >
        <X className="h-4 w-4" />
      </button>
      <div className="flex items-center gap-xs">
        <Rocket className="h-4 w-4 text-primary" />
        <span className="text-caption-uppercase uppercase text-muted dark:text-on-dark-soft">
          Update Available
        </span>
      </div>
      <p className="mt-xxs text-body-sm leading-snug text-ink dark:text-on-dark">
        Version {latestVersion} of CrowdSec Manager Mobile is ready to install.
      </p>
      {installUrl && (
        <a
          href={installUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-sm inline-flex items-center gap-xs text-body-sm font-medium text-primary hover:underline"
        >
          Update
          <ArrowRight className="h-3.5 w-3.5" />
        </a>
      )}
    </div>
  );
}
