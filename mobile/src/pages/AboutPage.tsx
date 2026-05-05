import { useState } from 'react';
import { ExternalLink } from 'lucide-react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { App as CapApp } from '@capacitor/app';
import { TopBar } from '@/components/TopBar';
import { Pill, Spike } from '@/components/design';

const links = [
  { label: 'Docs', href: 'https://hhf.technology' },
  { label: 'GitHub', href: 'https://github.com/HHFTechnology' },
  { label: 'Discourse', href: 'https://forum.hhf.technology' },
];

const social = [
  { label: 'X / Twitter', href: 'https://x.com/hhftechnology' },
  { label: 'Reddit', href: 'https://reddit.com/u/hhftechtips' },
  { label: 'Discord', href: 'https://discord.gg/HDCt9MjyMJ' },
];

export default function AboutPage() {
  const [appInfo, setAppInfo] = useState({ version: '3.0.0', build: '2026.03' });

  useMountEffect(() => {
    CapApp.getInfo()
      .then((info) => setAppInfo({ version: info.version, build: info.build }))
      .catch(() => {
        /* PWA fallback */
      });
  });

  return (
    <div className="pb-nav bg-canvas">
      <TopBar title="About" />

      <div className="px-md py-md space-y-md">
        <section className="rounded-lg bg-surface-card p-lg">
          <Spike className="w-6 h-6 text-ink" />
          <h2 className="mt-md font-display text-display-md text-ink">CrowdSec Manager</h2>
          <p className="text-body-sm text-muted">
            A mobile companion for your CrowdSec stack. Capacitor 7 · React 18 · TanStack Query.
          </p>
          <div className="mt-md flex items-center gap-xs">
            <Pill tone="cream">v{appInfo.version}</Pill>
            <Pill tone="cream">build {appInfo.build}</Pill>
          </div>
        </section>

        <section className="rounded-lg bg-surface-dark text-on-dark p-md">
          <div className="text-caption-uppercase uppercase text-on-dark-soft">Authored by</div>
          <div className="mt-xs font-display text-title-lg">HHF Technology</div>
          <p className="text-body-sm text-on-dark-soft mt-xxs">
            Open source security tooling for self-hosted infra.
          </p>
          <div className="mt-md grid grid-cols-3 gap-xs">
            {links.map((link) => (
              <a
                key={link.href}
                href={link.href}
                target="_blank"
                rel="noopener noreferrer"
                className="h-9 rounded-md bg-surface-dark-elevated text-on-dark text-button font-medium inline-flex items-center justify-center gap-xxs hover:bg-surface-dark-soft transition-colors"
              >
                {link.label}
              </a>
            ))}
          </div>
        </section>

        <section className="rounded-lg border border-hairline bg-canvas p-md">
          <div className="font-display text-title-md text-ink mb-sm">Community</div>
          <div className="space-y-xxs">
            {social.map((link) => (
              <a
                key={link.href}
                href={link.href}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between py-sm text-body-sm text-ink hover:text-primary transition-colors"
              >
                <span>{link.label}</span>
                <ExternalLink className="h-3.5 w-3.5 text-muted" />
              </a>
            ))}
          </div>
        </section>

        <section className="rounded-lg border border-hairline bg-canvas p-md">
          <div className="font-display text-title-md text-ink">License</div>
          <p className="text-caption text-muted-soft mt-xxs">MIT — see LICENSE for details.</p>
        </section>
      </div>
    </div>
  );
}
