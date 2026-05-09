import { useNavigate } from 'react-router-dom';
import { PageHeader } from '@/components/PageHeader';
import { cn } from '@/lib/utils';

interface Section {
  path: string;
  title: string;
  desc: string;
  count?: string;
  tone: 'cream' | 'dark' | 'coral';
}

const sections: Section[] = [
  {
    path: '/management/allowlists',
    title: 'Allowlists',
    desc: 'List, create, inspect, add/remove entries.',
    count: 'CIDR + IP',
    tone: 'cream',
  },
  {
    path: '/management/scenarios',
    title: 'Scenarios',
    desc: 'Setup, list files, delete.',
    count: 'YAML',
    tone: 'dark',
  },
  {
    path: '/management/hub',
    title: 'Hub',
    desc: 'Install collections, parsers, postoverflows.',
    count: 'Up to date',
    tone: 'cream',
  },
  {
    path: '/management/containers',
    title: 'Containers',
    desc: 'Start, stop, and restart Docker containers.',
    count: 'Docker',
    tone: 'cream',
  },
  {
    path: '/management/terminal',
    title: 'Terminal',
    desc: 'Interactive container shell.',
    tone: 'coral',
  },
];

const toneMap: Record<Section['tone'], string> = {
  cream: 'bg-surface-card text-ink',
  dark: 'bg-surface-dark text-on-dark',
  coral: 'bg-primary text-on-primary',
};

const mutedMap: Record<Section['tone'], string> = {
  cream: 'text-muted',
  dark: 'text-on-dark-soft',
  coral: 'opacity-90',
};

export default function ManagementPage() {
  const navigate = useNavigate();

  return (
    <div className="pb-nav bg-canvas">
      <PageHeader eyebrow="Manage" title="The control panel." subtitle="Endpoint-focused — pick a surface." />
      <div className="px-md pb-md space-y-sm">
        {sections.map((section, index) => (
          <button
            key={section.path}
            onClick={() => navigate(section.path)}
            className={cn(
              'w-full rounded-lg p-md text-left transition-all active:scale-[0.98] animate-fade-in',
              toneMap[section.tone],
            )}
            style={{ animationDelay: `${index * 40}ms` }}
          >
            <div className="flex items-start justify-between gap-md">
              <div className="min-w-0">
                <div className="font-display text-title-lg leading-tight">{section.title}</div>
                <div className={cn('text-caption mt-xxs', mutedMap[section.tone])}>{section.desc}</div>
              </div>
              <div className="flex items-center gap-xs shrink-0">
                {section.count && (
                  <span className={cn('text-caption', mutedMap[section.tone])}>{section.count}</span>
                )}
                <span className="w-7 h-7 rounded-pill border border-current/20 inline-flex items-center justify-center">
                  <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M9 6l6 6-6 6" />
                  </svg>
                </span>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
