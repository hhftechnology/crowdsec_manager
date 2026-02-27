import Link from 'next/link';
import type { Metadata } from 'next';
import { getSiteUrl } from '@/lib/seo';

const siteUrl = getSiteUrl();

export const metadata: Metadata = {
  title: 'Home',
  description:
    'CrowdSec Manager documentation home. Start with installation, quick start, features, and API references.',
  alternates: {
    canonical: '/',
  },
  openGraph: {
    type: 'website',
    url: siteUrl,
    title: 'CrowdSec Manager Documentation',
    description:
      'Start here for CrowdSec Manager setup, configuration, and API documentation.',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'CrowdSec Manager Documentation',
    description:
      'Start here for CrowdSec Manager setup, configuration, and API documentation.',
  },
};

const quickInstall = `services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:1.1.0
    container_name: crowdsec-manager
    restart: unless-stopped
    expose:
      - "8080"
    environment:
      - PORT=8080
      - ENVIRONMENT=production
      - TRAEFIK_DYNAMIC_CONFIG=/etc/traefik/dynamic_config.yml
      - TRAEFIK_CONTAINER_NAME=traefik
      - TRAEFIK_STATIC_CONFIG=/etc/traefik/traefik_config.yml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /root/config:/app/config
      - /root/docker-compose.yml:/app/docker-compose.yml
      - ./backups:/app/backups
      - ./data:/app/data
    networks:
      - pangolin

networks:
  pangolin:
    external: true`;

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col">
      <section className="border-b border-border/60 bg-gradient-to-b from-muted/40 to-background">
        <div className="container mx-auto px-4 py-16 text-center lg:py-20">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
            Stable Release
          </p>
          <h1 className="mb-4 text-4xl font-extrabold tracking-tight text-foreground lg:text-6xl">
            CrowdSec Manager 1.1.0
          </h1>
          <p className="mx-auto mb-8 max-w-3xl text-base text-muted-foreground lg:text-lg">
            Manage CrowdSec, Traefik integration, decisions, scenarios, logs, backups, and updates
            from a single web interface.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/docs/installation"
              className="rounded-md bg-primary px-6 py-3 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90"
            >
              Get Started
            </Link>
            <Link
              href="/docs/quick-start"
              className="rounded-md border border-input bg-background px-6 py-3 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground"
            >
              Quick Start
            </Link>
            <a
              href="https://github.com/hhftechnology/crowdsec_manager"
              target="_blank"
              rel="noreferrer"
              className="rounded-md border border-input bg-background px-6 py-3 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground"
            >
              GitHub
            </a>
          </div>
        </div>
      </section>

      <section className="container mx-auto grid gap-4 px-4 py-10 md:grid-cols-2 lg:grid-cols-4">
        {[
          'Health, alerts, and decision visibility in one dashboard',
          'Service lifecycle actions and container-aware stack operations',
          'Scenario, allowlist, and captcha configuration workflows',
          'Backup, restore, logs, and update operations from the UI',
        ].map((item) => (
          <div key={item} className="rounded-lg border bg-card p-4 text-sm text-card-foreground">
            {item}
          </div>
        ))}
      </section>

      <section className="container mx-auto px-4 pb-16">
        <div className="mb-4 flex items-center justify-between gap-4">
          <h2 className="text-xl font-semibold tracking-tight">Minimum Compose</h2>
          <Link className="text-sm text-primary hover:underline" href="/docs/installation">
            Full installation guide
          </Link>
        </div>
        <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-4 text-xs sm:text-sm">
          <code>{quickInstall}</code>
        </pre>
      </section>
    </main>
  );
}
