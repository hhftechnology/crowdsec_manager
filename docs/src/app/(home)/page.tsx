import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col justify-center text-center">
      <div className="container mx-auto px-4 py-16">
        <h1 className="mb-4 text-4xl font-extrabold tracking-tight text-foreground lg:text-6xl">
          CrowdSec Manager
        </h1>
        <p className="mb-8 text-lg text-muted-foreground lg:text-xl">
          The comprehensive dashboard for managing your CrowdSec instance.
          <br />
          Monitor alerts, manage decisions, and configure your security stack with ease.
        </p>
        <div className="flex justify-center gap-4">
          <Link
            href="/docs"
            className="rounded-md bg-primary px-6 py-3 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            Get Started
          </Link>
          <a
            href="https://github.com/hhftechnology/crowdsec_manager"
            target="_blank"
            rel="noreferrer"
            className="rounded-md border border-input bg-background px-6 py-3 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            GitHub
          </a>
        </div>
      </div>
    </main>
  );
}
