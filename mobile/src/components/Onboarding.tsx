import { useCallback, useRef, useState } from 'react';
import { cn } from '@/lib/utils';
import { ButtonPrimary, Dot, Spike, UpperBadge, Wordmark } from '@/components/design';

interface SlideContent {
  step: string;
  eyebrow: string;
  title: string;
  description: string;
  feed?: { time: string; line: string; tone?: 'amber' | 'teal' | 'on-dark' }[];
  note?: { title: string; body: string };
}

const slides: SlideContent[] = [
  {
    step: 'Step 01 / 04',
    eyebrow: 'Welcome',
    title: 'A literary console for your stack.',
    description:
      'CrowdSec Manager is a mobile companion for your security infrastructure — read like a column, scan like a console.',
    note: {
      title: "Editor's note",
      body: 'Tap any tab to dive in. Settings live behind the gear; the terminal is one tap from Manage.',
    },
  },
  {
    step: 'Step 02 / 04',
    eyebrow: 'Live security',
    title: 'Real-time security, the editorial way.',
    description:
      'View live decisions and alerts. Check IP reputation, unban addresses, and stay on top of threats as they happen.',
    feed: [
      { time: '14:02', line: 'ban 91.214.78.10' },
      { time: '14:01', line: 'crowdsec/http-bf', tone: 'amber' },
      { time: '14:01', line: 'captcha 203.0.113.4' },
      { time: '14:00', line: 'unban 10.0.4.21', tone: 'teal' },
    ],
    note: {
      title: "Editor's note",
      body: 'Tap & hold any IP to inspect. Swipe a card to ban or whitelist in one motion.',
    },
  },
  {
    step: 'Step 03 / 04',
    eyebrow: 'Manage',
    title: 'The control panel, in your pocket.',
    description:
      'Manage allowlists, scenarios, hub items, and bouncers. Access container terminals and view structured logs — all from your phone.',
    note: {
      title: "Editor's note",
      body: 'The terminal speaks WebSocket; long-running sessions reconnect automatically.',
    },
  },
  {
    step: 'Step 04 / 04',
    eyebrow: 'Connect',
    title: 'Connect once. Read everywhere.',
    description:
      'Connect to your CrowdSec Manager server to get started. Your security infrastructure is one tap away.',
    note: {
      title: "Editor's note",
      body: 'You can switch profiles at any time from Settings → API connection.',
    },
  },
];

const SWIPE_THRESHOLD = 50;
const STORAGE_KEY = 'csm_onboarding_complete';

interface OnboardingProps {
  onComplete: () => void;
}

export function Onboarding({ onComplete }: OnboardingProps) {
  const [current, setCurrent] = useState(0);
  const touchStartX = useRef(0);

  const finish = useCallback(() => {
    localStorage.setItem(STORAGE_KEY, 'true');
    onComplete();
  }, [onComplete]);

  const next = () => {
    if (current < slides.length - 1) setCurrent(current + 1);
    else finish();
  };

  const prev = () => {
    if (current > 0) setCurrent(current - 1);
  };

  const handleTouchStart = (e: React.TouchEvent) => {
    touchStartX.current = e.touches[0].clientX;
  };

  const handleTouchEnd = (e: React.TouchEvent) => {
    const delta = touchStartX.current - e.changedTouches[0].clientX;
    if (delta > SWIPE_THRESHOLD) next();
    else if (delta < -SWIPE_THRESHOLD) prev();
  };

  const slide = slides[current];
  const isLast = current === slides.length - 1;

  const feedToneClass = (tone?: 'amber' | 'teal' | 'on-dark') => {
    if (tone === 'amber') return 'text-accent-amber';
    if (tone === 'teal') return 'text-accent-teal';
    return 'text-on-dark';
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex flex-col bg-canvas safe-top safe-bottom"
      onTouchStart={handleTouchStart}
      onTouchEnd={handleTouchEnd}
    >
      <div className="px-md pt-md flex items-center justify-between">
        <Wordmark />
        {!isLast ? (
          <button onClick={finish} className="text-button text-muted hover:text-ink">
            Skip
          </button>
        ) : (
          <span />
        )}
      </div>

      <div className="flex-1 px-md pt-lg overflow-y-auto pb-md">
        <UpperBadge tone="coral">{slide.step}</UpperBadge>
        <div className="flex items-center gap-xs mt-sm text-caption-uppercase uppercase font-medium text-muted">
          <Spike className="w-3 h-3 text-ink" />
          {slide.eyebrow}
        </div>
        <h2 className="mt-xs font-display text-display-md text-ink">{slide.title}</h2>
        <p className="mt-sm text-body-md text-body">{slide.description}</p>

        {slide.feed && (
          <div className="mt-lg rounded-lg bg-surface-dark p-lg text-on-dark space-y-sm">
            <div className="flex items-center gap-xs text-on-dark-soft text-caption-uppercase uppercase">
              <Dot tone="teal" pulse /> live feed
            </div>
            <div className="font-mono text-code space-y-[6px]">
              {slide.feed.map((row, i) => (
                <div key={i} className="flex justify-between">
                  <span className="text-on-dark-soft">{row.time}</span>
                  <span className={feedToneClass(row.tone)}>{row.line}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {slide.note && (
          <div className="mt-lg rounded-lg bg-surface-card p-md">
            <div className="flex items-center gap-sm">
              <div className="w-10 h-10 rounded-md bg-canvas border border-hairline flex items-center justify-center">
                <Spike />
              </div>
              <div className="min-w-0">
                <div className="text-title-sm font-medium text-ink">{slide.note.title}</div>
                <div className="text-caption text-muted">{slide.note.body}</div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="px-md pb-md pt-md space-y-md">
        <div className="flex justify-center gap-xs">
          {slides.map((_, i) => (
            <button
              key={i}
              onClick={() => setCurrent(i)}
              aria-label={`Go to slide ${i + 1}`}
              className={cn(
                'h-1.5 rounded-pill transition-all',
                i === current ? 'w-6 bg-primary' : 'w-1.5 bg-muted-soft/40',
              )}
            />
          ))}
        </div>
        <ButtonPrimary onClick={next} full size="lg">
          {isLast ? 'Get Started' : 'Next'}
        </ButtonPrimary>
      </div>
    </div>
  );
}
