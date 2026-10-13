// Small building blocks the pages share. Styling lives in styles.css; these
// just keep the markup for each piece in one place.
import { type JSX, type ReactNode, useEffect, useRef, useState } from "react";

export type Tone = "ok" | "warn" | "err" | "idle" | "accent" | "neutral";

export function Logo({ size = 20 }: { size?: number }): JSX.Element {
  return (
    <svg className="logo" width={size} height={size} viewBox="140 145 810 795" aria-hidden>
      <path
        className="logo-body"
        d="M191 194 L338 276 L338 460 L460 523 L460 382 C425 333 406 259 389 194 L571 262 C640 289 713 325 762 359 C801 386 822 422 832 462 C877 486 902 519 902 563 C902 602 886 632 859 656 C860 622 844 599 811 583 C765 561 707 555 638 565 L638 775 L460 890 L460 664 L339 595 L339 827 L191 725 Z"
      />
    </svg>
  );
}

export function Dot({ tone, title }: { tone: Tone; title?: string }): JSX.Element {
  return <span className={`dot tone-${tone}`} title={title} aria-hidden={title === undefined} />;
}

export function Tag({
  tone,
  solid = false,
  title,
  children,
}: {
  tone?: Tone;
  solid?: boolean;
  title?: string;
  children: ReactNode;
}): JSX.Element {
  const className = ["tag", tone !== undefined && `tone-${tone}`, solid && "solid"].filter(Boolean).join(" ");
  return (
    <span className={className} title={title}>
      {children}
    </span>
  );
}

// Four registration marks at the corners of the nearest positioned parent.
export function Corners(): JSX.Element {
  return (
    <>
      <span className="corner tl" aria-hidden />
      <span className="corner tr" aria-hidden />
      <span className="corner bl" aria-hidden />
      <span className="corner br" aria-hidden />
    </>
  );
}

export function Metric({
  label,
  children,
  dim = false,
}: {
  label: string;
  children: ReactNode;
  dim?: boolean;
}): JSX.Element {
  return (
    <div className="metric">
      <span className="label">{label}</span>
      <span className={dim ? "metric-value dim" : "metric-value"}>{children}</span>
    </div>
  );
}

export function Alert({ children, ok = false }: { children: ReactNode; ok?: boolean }): JSX.Element {
  return (
    <div className={ok ? "alert ok" : "alert"} role={ok ? "status" : "alert"}>
      <Tag tone={ok ? "ok" : "err"}>{ok ? "Done" : "Error"}</Tag>
      <span>{children}</span>
    </div>
  );
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
  small = false,
  label,
  disabled = false,
}: {
  options: readonly (readonly [T, string])[];
  value: T;
  onChange: (value: T) => void;
  small?: boolean;
  label: string;
  disabled?: boolean;
}): JSX.Element {
  return (
    <div className={small ? "seg seg-sm" : "seg"} role="group" aria-label={label}>
      {options.map(([option, text]) => (
        <button
          key={option}
          type="button"
          aria-pressed={option === value}
          disabled={disabled}
          onClick={() => option !== value && onChange(option)}
        >
          {text}
        </button>
      ))}
    </div>
  );
}

// Copies `value` and says so for a moment.
export function CopyButton({ value, small = false }: { value: string; small?: boolean }): JSX.Element {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = (): void => {
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <button type="button" className={small ? "btn btn-sm" : "btn"} onClick={copy}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

// A value shown in a code box with a copy button beside it.
export function CodeBlock({ value, big = false }: { value: string; big?: boolean }): JSX.Element {
  return (
    <div className={big ? "codeblock big" : "codeblock"}>
      <code>{value}</code>
      <CopyButton value={value} />
    </div>
  );
}

// A destructive button that asks twice: the first click arms it, the second
// within a few seconds goes through. Saves a native confirm() dialog.
export function ConfirmButton({
  children,
  confirmLabel,
  onConfirm,
  small = false,
  disabled = false,
}: {
  children: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  small?: boolean;
  disabled?: boolean;
}): JSX.Element {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const timer = window.setTimeout(() => setArmed(false), 4000);
    return () => window.clearTimeout(timer);
  }, [armed]);

  const className = ["btn", "btn-danger", small && "btn-sm", armed && "armed"].filter(Boolean).join(" ");
  return (
    <button
      type="button"
      className={className}
      disabled={disabled}
      onBlur={() => setArmed(false)}
      onClick={() => {
        if (!armed) {
          setArmed(true);
          return;
        }
        setArmed(false);
        onConfirm();
      }}
    >
      {armed ? confirmLabel : children}
    </button>
  );
}

// The current time, re-read every `intervalMs`.
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

export function errorMessage(error: unknown, fallback = "request failed"): string {
  if (error instanceof Error) return error.message;
  // Tauri commands fail with their error as a plain string.
  if (typeof error === "string" && error !== "") return error;
  return fallback;
}
