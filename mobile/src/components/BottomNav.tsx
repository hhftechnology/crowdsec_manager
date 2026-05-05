import { useLocation, useNavigate } from 'react-router-dom';
import { cn } from '@/lib/utils';

interface Tab {
  path: string;
  label: string;
  glyph: string;
}

const tabs: Tab[] = [
  {
    path: '/dashboard',
    label: 'Overview',
    glyph: 'M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z',
  },
  {
    path: '/security',
    label: 'Security',
    glyph: 'M12 2 4 5v6c0 5 3.5 9.5 8 11 4.5-1.5 8-6 8-11V5l-8-3Z',
  },
  {
    path: '/logs',
    label: 'Logs',
    glyph: 'M5 4h14v3H5V4Zm0 6h14v3H5v-3Zm0 6h9v3H5v-3Z',
  },
  {
    path: '/management',
    label: 'Manage',
    glyph: 'M19.4 13a7.49 7.49 0 0 0 0-2l2-1.6-2-3.4-2.4 1a7.5 7.5 0 0 0-1.7-1l-.4-2.5h-4l-.4 2.5a7.5 7.5 0 0 0-1.7 1l-2.4-1-2 3.4 2 1.6a7.49 7.49 0 0 0 0 2l-2 1.6 2 3.4 2.4-1c.5.4 1.1.8 1.7 1l.4 2.5h4l.4-2.5c.6-.2 1.2-.5 1.7-1l2.4 1 2-3.4-2-1.6ZM12 15.5A3.5 3.5 0 1 1 12 8.5a3.5 3.5 0 0 1 0 7Z',
  },
  {
    path: '/more',
    label: 'Settings',
    glyph: 'M4 6h16v2H4V6Zm0 5h16v2H4v-2Zm0 5h16v2H4v-2Z',
  },
];

export function BottomNav() {
  const location = useLocation();
  const navigate = useNavigate();

  return (
    <nav className="fixed bottom-0 left-0 right-0 z-50 border-t border-hairline bg-canvas/95 backdrop-blur-md safe-bottom">
      <div className="flex items-center justify-around h-16 max-w-lg mx-auto px-xs">
        {tabs.map((tab) => {
          const active = location.pathname.startsWith(tab.path);
          return (
            <button
              key={tab.path}
              onClick={() => navigate(tab.path)}
              className={cn(
                'flex flex-col items-center gap-[2px] px-sm py-xs rounded-md min-w-[60px] transition-colors',
                active ? 'text-primary' : 'text-muted hover:text-ink',
              )}
              aria-label={tab.label}
            >
              <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
                <path d={tab.glyph} />
              </svg>
              <span className="text-caption-uppercase font-medium uppercase">{tab.label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
