import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { cn } from '@/lib/utils';

interface TopBarProps {
  title: string;
  right?: ReactNode;
  back?: boolean;
  onBack?: () => void;
  className?: string;
}

export function TopBar({ title, right, back = true, onBack, className }: TopBarProps) {
  const navigate = useNavigate();
  const handleBack = () => {
    if (onBack) onBack();
    else navigate(-1);
  };

  return (
    <div
      className={cn(
        'px-md py-sm flex items-center justify-between border-b border-hairline-soft bg-canvas',
        className,
      )}
    >
      <div className="flex items-center gap-sm min-w-0">
        {back && (
          <button
            onClick={handleBack}
            aria-label="Back"
            className="w-9 h-9 rounded-pill border border-hairline bg-canvas inline-flex items-center justify-center text-ink shrink-0 hover:bg-surface-soft transition-colors"
          >
            <svg viewBox="0 0 24 24" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M15 18l-6-6 6-6" />
            </svg>
          </button>
        )}
        <span className="font-display text-title-md text-ink truncate">{title}</span>
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}
