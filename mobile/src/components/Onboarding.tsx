import { useCallback, useRef, useState } from 'react';
import { Shield, Activity, Settings, Rocket } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface Slide {
  icon: React.ElementType;
  title: string;
  description: string;
  gradient: string;
}

const slides: Slide[] = [
  {
    icon: Shield,
    title: 'Welcome to CrowdSec Manager',
    description:
      'Your mobile command center for CrowdSec security infrastructure. Monitor, manage, and protect your servers from anywhere.',
    gradient: 'from-[hsl(348,56%,27%)] to-[hsl(348,45%,18%)]',
  },
  {
    icon: Activity,
    title: 'Real-Time Security',
    description:
      'View live decisions, alerts, and metrics. Check IP reputation, unban addresses, and stay on top of threats as they happen.',
    gradient: 'from-[hsl(348,45%,22%)] to-[hsl(348,56%,15%)]',
  },
  {
    icon: Settings,
    title: 'Full Management',
    description:
      'Manage allowlists, scenarios, hub items, and bouncers. Access container terminals and view structured logs — all from your phone.',
    gradient: 'from-[hsl(348,56%,15%)] to-[hsl(348,30%,10%)]',
  },
  {
    icon: Rocket,
    title: 'Get Started',
    description:
      'Connect to your CrowdSec Manager server to get started. Your security infrastructure is one tap away.',
    gradient: 'from-[hsl(348,40%,20%)] to-[hsl(348,56%,27%)]',
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

  return (
    <div
      className={cn(
        'fixed inset-0 z-[100] flex flex-col items-center justify-between bg-gradient-to-br transition-all duration-500',
        slide.gradient,
      )}
      onTouchStart={handleTouchStart}
      onTouchEnd={handleTouchEnd}
    >
      {/* Skip button */}
      {!isLast && (
        <div className="w-full flex justify-end p-4 safe-top">
          <Button
            variant="ghost"
            onClick={finish}
            className="text-white/70 hover:text-white hover:bg-white/10"
          >
            Skip
          </Button>
        </div>
      )}
      {isLast && <div className="safe-top" />}

      {/* Slide content */}
      <div className="flex-1 flex flex-col items-center justify-center px-8 max-w-sm">
        <div className="flex h-24 w-24 items-center justify-center rounded-3xl bg-white/15 backdrop-blur-sm mb-8 shadow-lg">
          <slide.icon className="h-12 w-12 text-white" />
        </div>
        <h2 className="text-2xl font-bold text-white text-center mb-4 text-balance">
          {slide.title}
        </h2>
        <p className="text-base text-white/80 text-center leading-relaxed text-balance">
          {slide.description}
        </p>
      </div>

      {/* Bottom: dots + button */}
      <div className="w-full px-8 pb-6 safe-bottom space-y-6">
        {/* Dots */}
        <div className="flex justify-center gap-2">
          {slides.map((_, i) => (
            <button
              key={i}
              onClick={() => setCurrent(i)}
              className={cn(
                'h-2 rounded-full transition-all duration-300',
                i === current ? 'w-8 bg-white' : 'w-2 bg-white/40',
              )}
            />
          ))}
        </div>

        {/* Action button */}
        <Button
          onClick={next}
          className="w-full h-14 rounded-xl text-base font-semibold bg-white text-[hsl(348,56%,20%)] hover:bg-white/90"
        >
          {isLast ? 'Get Started' : 'Next'}
        </Button>
      </div>
    </div>
  );
}
