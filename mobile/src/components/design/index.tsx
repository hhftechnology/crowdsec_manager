import { ReactNode, ButtonHTMLAttributes, LabelHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export const Spike = ({ className = "w-3 h-3" }: { className?: string }) => (
  <svg viewBox="0 0 16 16" className={className} fill="currentColor" aria-hidden="true">
    <path d="M8 0 L9 7 L16 8 L9 9 L8 16 L7 9 L0 8 L7 7 Z" />
  </svg>
);

export const Wordmark = ({ tone = "ink" }: { tone?: "ink" | "on-dark" }) => (
  <div className={cn("flex items-center gap-xs", tone === "on-dark" ? "text-on-dark" : "text-ink")}>
    <Spike className="w-3.5 h-3.5" />
    <span className="font-display text-title-md">Crowdsec</span>
  </div>
);

export type PillTone = "cream" | "coral" | "teal" | "amber" | "dark" | "success" | "error" | "outline" | "warning";

const pillToneMap: Record<PillTone, string> = {
  cream: "bg-surface-card text-ink",
  coral: "bg-primary text-on-primary",
  teal: "bg-accent-teal/15 text-accent-teal",
  amber: "bg-accent-amber/20 text-ink",
  dark: "bg-surface-dark-elevated text-on-dark",
  success: "bg-success/15 text-success",
  error: "bg-error/15 text-error",
  warning: "bg-warning/15 text-warning",
  outline: "border border-hairline text-body",
};

export const Pill = ({
  children,
  tone = "cream",
  className,
}: {
  children: ReactNode;
  tone?: PillTone;
  className?: string;
}) => (
  <span
    className={cn(
      "inline-flex items-center gap-xxs rounded-pill px-sm py-xxs text-caption font-medium",
      pillToneMap[tone],
      className,
    )}
  >
    {children}
  </span>
);

export type UpperBadgeTone = "coral" | "cream" | "dark";
const upperBadgeMap: Record<UpperBadgeTone, string> = {
  coral: "bg-primary text-on-primary",
  cream: "bg-surface-cream-strong text-ink",
  dark: "bg-surface-dark-elevated text-on-dark",
};

export const UpperBadge = ({
  children,
  tone = "coral",
  className,
}: {
  children: ReactNode;
  tone?: UpperBadgeTone;
  className?: string;
}) => (
  <span
    className={cn(
      "inline-flex items-center rounded-pill px-sm py-xxs text-caption-uppercase font-medium uppercase",
      upperBadgeMap[tone],
      className,
    )}
  >
    {children}
  </span>
);

export type DotTone = "success" | "warning" | "error" | "teal" | "muted" | "coral";
const dotMap: Record<DotTone, string> = {
  success: "bg-success",
  warning: "bg-warning",
  error: "bg-error",
  teal: "bg-accent-teal",
  muted: "bg-muted-soft",
  coral: "bg-primary",
};

export const Dot = ({ tone = "success", pulse = false }: { tone?: DotTone; pulse?: boolean }) => (
  <span className={cn("inline-block w-2 h-2 rounded-pill", dotMap[tone], pulse && "animate-pulse")} />
);

type ButtonSize = "sm" | "md" | "lg";
const sizeMap: Record<ButtonSize, string> = {
  sm: "h-9 px-md text-button",
  md: "h-10 px-lg text-button",
  lg: "h-12 px-xl text-button",
};

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  full?: boolean;
  size?: ButtonSize;
  dark?: boolean;
};

export const ButtonPrimary = ({ full, size = "md", className, children, ...rest }: ButtonProps) => (
  <button
    {...rest}
    className={cn(
      sizeMap[size],
      full && "w-full",
      "bg-primary text-on-primary rounded-md font-sans font-medium inline-flex items-center justify-center gap-xs",
      "transition-colors hover:bg-primary-active disabled:bg-primary-disabled disabled:text-muted disabled:cursor-not-allowed",
      className,
    )}
  >
    {children}
  </button>
);

export const ButtonSecondary = ({ full, size = "md", dark, className, children, ...rest }: ButtonProps) => (
  <button
    {...rest}
    className={cn(
      sizeMap[size],
      full && "w-full",
      "rounded-md font-sans font-medium inline-flex items-center justify-center gap-xs transition-colors",
      dark
        ? "bg-surface-dark-elevated text-on-dark border border-on-dark/10 hover:bg-surface-dark-soft"
        : "bg-canvas text-ink border border-hairline hover:bg-surface-soft",
      "disabled:opacity-60 disabled:cursor-not-allowed",
      className,
    )}
  >
    {children}
  </button>
);

export const TextLink = ({
  children,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { children: ReactNode }) => (
  <button
    {...rest}
    className={cn(
      "text-primary underline underline-offset-2 decoration-primary/40 font-medium text-body-sm",
      className,
    )}
  >
    {children}
  </button>
);

type CategoryTabProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  active?: boolean;
};

export const CategoryTab = ({ active, className, children, ...rest }: CategoryTabProps) => (
  <button
    {...rest}
    className={cn(
      "px-sm py-xxs rounded-md text-button font-medium transition-colors whitespace-nowrap",
      active ? "bg-surface-card text-ink" : "text-muted hover:text-ink",
      className,
    )}
  >
    {children}
  </button>
);

export const FieldLabel = ({
  children,
  className,
  ...rest
}: LabelHTMLAttributes<HTMLLabelElement>) => (
  <label
    {...rest}
    className={cn("text-caption-uppercase font-medium text-muted uppercase", className)}
  >
    {children}
  </label>
);

export const Bars = ({
  values,
  tone = "primary",
  height = 56,
}: {
  values: number[];
  tone?: "primary" | "teal" | "dark";
  height?: number;
}) => {
  const max = Math.max(...values, 1);
  const allZero = values.length > 0 && values.every((v) => v <= 0);
  const barColor =
    tone === "primary" ? "bg-primary" : tone === "teal" ? "bg-accent-teal" : "bg-on-dark/80";
  if (values.length === 0) {
    return <div style={{ height }} aria-hidden />;
  }
  return (
    <div className="flex items-end gap-[3px]" style={{ height }} role="img" aria-label="activity">
      {values.map((v, i) => {
        const pct = allZero ? 18 : Math.max((v / max) * 100, 12);
        return (
          <div
            key={i}
            className={cn("w-[6px] rounded-xs", barColor, allZero && "opacity-40")}
            style={{ height: `${pct}%`, minHeight: 4 }}
          />
        );
      })}
    </div>
  );
};

type DonutColor = "primary" | "accent-teal" | "accent-amber" | "success" | "warning" | "error";

const donutColorClass: Record<DonutColor, string> = {
  primary: "text-primary",
  "accent-teal": "text-accent-teal",
  "accent-amber": "text-accent-amber",
  success: "text-success",
  warning: "text-warning",
  error: "text-error",
};

export const Donut = ({
  segments,
  size = 92,
}: {
  segments: { value: number; color: DonutColor }[];
  size?: number;
}) => {
  const positiveSegments = segments
    .map((segment) => ({ ...segment, value: Math.max(0, segment.value) }))
    .filter((segment) => segment.value > 0);
  const total = positiveSegments.reduce((a, b) => a + b.value, 0);
  const r = 36;
  const c = 2 * Math.PI * r;
  let acc = 0;
  return (
    <svg width={size} height={size} viewBox="0 0 92 92">
      <circle
        cx="46"
        cy="46"
        r={r}
        fill="none"
        stroke="currentColor"
        strokeWidth="10"
        className={
          total === 0
            ? "text-hairline dark:text-on-dark-soft/30"
            : "text-hairline-soft dark:text-on-dark-soft/20"
        }
      />
      {positiveSegments.map((s, i) => {
        const len = (s.value / total) * c;
        const dash = `${len} ${c - len}`;
        const offset = c / 4 - acc;
        acc += len;
        return (
          <circle
            key={i}
            cx="46"
            cy="46"
            r={r}
            fill="none"
            className={donutColorClass[s.color]}
            stroke="currentColor"
            strokeWidth="10"
            strokeDasharray={dash}
            strokeDashoffset={offset}
            transform="rotate(-90 46 46)"
          />
        );
      })}
    </svg>
  );
};
