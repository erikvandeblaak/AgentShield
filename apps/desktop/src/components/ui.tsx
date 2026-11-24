import {
  useId, useState, type ButtonHTMLAttributes, type CSSProperties, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes,
} from "react";
import { AlertTriangle, Check, ChevronDown, Copy, Info, Loader2, OctagonAlert, RefreshCw, ShieldCheck, type LucideIcon } from "lucide-react";
import { copyText, type AsyncState } from "../lib/hooks";
import { useT } from "../i18n";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

// ------------------------------------------------------------------ Button

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "outline-danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "sm" | "md";
  icon?: LucideIcon;
  loading?: boolean;
}

const BTN: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-fg hover:brightness-110 font-semibold shadow-[0_1px_0_rgb(255_255_255/0.2)_inset]",
  secondary: "bg-surface-2 text-fg border border-line-strong hover:bg-surface-3",
  ghost: "text-fg-2 hover:text-fg hover:bg-surface-2",
  danger: "bg-danger text-bg font-semibold hover:brightness-110",
  "outline-danger": "border border-danger/50 text-danger hover:bg-danger/10",
};

export function Button({ variant = "secondary", size = "md", icon: Icon, loading, children, className, disabled, type, ...rest }: ButtonProps) {
  return (
    <button
      type={type ?? "button"}
      disabled={disabled || loading}
      className={cx(
        "inline-flex shrink-0 items-center justify-center gap-2 rounded-lg whitespace-nowrap transition-[background-color,filter,color] duration-150",
        "disabled:opacity-50",
        size === "sm" ? "h-8 px-3 text-sm" : "h-9.5 px-4 text-base",
        BTN[variant],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="size-4 animate-spin" aria-hidden /> : Icon ? <Icon className="size-4" aria-hidden /> : null}
      {children}
    </button>
  );
}

export function IconButton({ icon: Icon, label, className, ...rest }: { icon: LucideIcon; label: string } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cx("inline-flex size-9 shrink-0 items-center justify-center rounded-lg text-fg-2 transition-colors hover:bg-surface-2 hover:text-fg disabled:opacity-50", className)}
      {...rest}
    >
      <Icon className="size-4.5" aria-hidden />
    </button>
  );
}

// ------------------------------------------------------------------ Card

interface CardProps {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  bodyClassName?: string;
  padded?: boolean;
  /** CSS colour (e.g. "var(--danger)") for a thin accent line on top. */
  accent?: string;
}

export function Card({ title, subtitle, actions, children, className, bodyClassName, padded = true, accent }: CardProps) {
  return (
    <section
      className={cx("relative flex min-w-0 flex-col rounded-xl border border-line bg-surface shadow-card", className)}
      style={accent ? { boxShadow: `inset 0 2px 0 0 ${accent}, var(--shadow-card)` } : undefined}
    >
      {(title || actions) && (
        <header className="flex min-h-13 items-start justify-between gap-4 px-5 pt-4 pb-1">
          <div className="min-w-0">
            {title && <h3 className="text-lg leading-6 font-semibold text-fg">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-sm text-fg-3">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx("min-h-0 min-w-0 flex-1", padded && "px-5 pt-3 pb-5", bodyClassName)}>{children}</div>
    </section>
  );
}

// ------------------------------------------------------------------ Page header

export function PageHeader({ title, description, actions, icon: Icon }: { title: string; description?: ReactNode; actions?: ReactNode; icon?: LucideIcon }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div className="flex min-w-0 items-start gap-3.5">
        {Icon && (
          <div className="mt-0.5 flex size-10 shrink-0 items-center justify-center rounded-xl border border-line bg-surface text-accent-2">
            <Icon className="size-5" aria-hidden />
          </div>
        )}
        <div className="min-w-0">
          <h1 className="text-3xl leading-9 font-semibold tracking-tight text-fg">{title}</h1>
          {description && <p className="mt-1 max-w-3xl text-base text-fg-2">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function SectionTitle({ children, hint, actions }: { children: ReactNode; hint?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-3 flex items-end justify-between gap-4">
      <div>
        <h2 className="text-xl font-semibold text-fg">{children}</h2>
        {hint && <p className="mt-0.5 text-sm text-fg-3">{hint}</p>}
      </div>
      {actions}
    </div>
  );
}

// ------------------------------------------------------------------ KPI tile

interface KpiProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: LucideIcon;
  /** CSS colour for the icon + accent, e.g. "var(--danger)". Omit for neutral. */
  tone?: string;
  /** Highlights the tile (used when a value needs attention, e.g. dropped events > 0). */
  alert?: boolean;
  onClick?: () => void;
  title?: string;
}

export function Kpi({ label, value, hint, icon: Icon, tone, alert, onClick, title }: KpiProps) {
  const body = (
    <>
      <div className="eyebrow truncate" title={label}>{label}</div>
      <div className="mt-2 flex items-center justify-between gap-2">
        <span className="tabular text-3xl leading-9 font-semibold tracking-tight text-fg">{value}</span>
        {Icon && <Icon className="size-4.5 shrink-0" style={{ color: tone ?? "var(--fg-3)" }} aria-hidden />}
      </div>
      {hint && <div className="mt-1 line-clamp-2 text-sm leading-snug text-fg-3">{hint}</div>}
    </>
  );
  const cls = cx(
    "relative flex min-w-0 flex-col items-stretch justify-start rounded-xl border bg-surface px-4 py-3.5 text-left shadow-card transition-colors",
    alert ? "border-(--tone)/60" : "border-line",
    onClick && "hover:border-line-strong hover:bg-surface-2",
  );
  const style = { "--tone": tone ?? "var(--fg-3)", ...(alert ? { background: "color-mix(in srgb, var(--tone) 7%, var(--surface))" } : {}) } as CSSProperties;
  return onClick ? (
    <button type="button" className={cls} style={style} onClick={onClick} title={title}>{body}</button>
  ) : (
    <div className={cls} style={style} title={title}>{body}</div>
  );
}

// ------------------------------------------------------------------ Badge

interface BadgeProps {
  /** CSS colour, e.g. "var(--danger)". */
  tone?: string;
  children: ReactNode;
  dot?: boolean;
  solid?: boolean;
  title?: string;
  className?: string;
  icon?: LucideIcon;
}

export function Badge({ tone = "var(--fg-3)", children, dot, solid, title, className, icon: Icon }: BadgeProps) {
  return (
    <span
      title={title}
      style={{ "--tone": tone } as CSSProperties}
      className={cx(
        "inline-flex h-6 max-w-full items-center gap-1.5 rounded-md px-2 text-xs font-medium whitespace-nowrap",
        solid ? "tone-solid font-semibold" : "tone",
        className,
      )}
    >
      {dot && <span className="size-1.5 shrink-0 rounded-full bg-current" aria-hidden />}
      {Icon && <Icon className="size-3.5 shrink-0" aria-hidden />}
      <span className="truncate">{children}</span>
    </span>
  );
}

// ------------------------------------------------------------------ Callout

type CalloutTone = "info" | "warn" | "danger" | "ok" | "neutral";
const CALLOUT: Record<CalloutTone, { color: string; icon: LucideIcon }> = {
  info: { color: "var(--info)", icon: Info },
  warn: { color: "var(--warn)", icon: AlertTriangle },
  danger: { color: "var(--danger)", icon: OctagonAlert },
  ok: { color: "var(--ok)", icon: ShieldCheck },
  neutral: { color: "var(--fg-3)", icon: Info },
};

export function Callout({ tone = "info", title, children, icon, className }: { tone?: CalloutTone; title?: ReactNode; children?: ReactNode; icon?: LucideIcon; className?: string }) {
  const Icon = icon ?? CALLOUT[tone].icon;
  return (
    <div
      role="note"
      style={{ "--tone": CALLOUT[tone].color, background: "color-mix(in srgb, var(--tone) 8%, var(--surface))", borderColor: "color-mix(in srgb, var(--tone) 30%, var(--line))" } as CSSProperties}
      className={cx("flex gap-3 rounded-xl border px-4 py-3", className)}
    >
      <Icon className="mt-0.5 size-4.5 shrink-0 text-(--tone)" aria-hidden />
      <div className="min-w-0 text-base text-fg-2">
        {title && <div className="font-semibold text-fg">{title}</div>}
        {children}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ States

export function EmptyState({ icon: Icon = Info, title, body, action, compact }: { icon?: LucideIcon; title: string; body?: ReactNode; action?: ReactNode; compact?: boolean }) {
  return (
    <div className={cx("flex flex-col items-center justify-center text-center", compact ? "px-4 py-8" : "px-6 py-14")}>
      <div className="flex size-11 items-center justify-center rounded-full border border-line bg-surface-2 text-fg-3">
        <Icon className="size-5" aria-hidden />
      </div>
      <div className="mt-3 text-lg font-semibold text-fg">{title}</div>
      {body && <p className="mt-1 max-w-md text-base text-fg-3">{body}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, compact }: { error: string; onRetry?: () => void; compact?: boolean }) {
  const t = useT();
  return (
    <div role="alert" className={cx("flex flex-col items-center justify-center text-center", compact ? "px-4 py-8" : "px-6 py-14")}>
      <div className="flex size-11 items-center justify-center rounded-full border border-danger/40 bg-danger/10 text-danger">
        <OctagonAlert className="size-5" aria-hidden />
      </div>
      <div className="mt-3 text-lg font-semibold text-fg">{t.common.errorTitle}</div>
      <p className="mt-1 max-w-md text-base text-fg-3">{t.common.errorBody}</p>
      <pre className="mt-3 max-h-28 max-w-xl overflow-auto rounded-lg border border-line bg-surface-2 px-3 py-2 text-left text-sm whitespace-pre-wrap text-fg-2">{error}</pre>
      {onRetry && <Button className="mt-4" icon={RefreshCw} onClick={onRetry}>{t.common.retry}</Button>}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cx("animate-pulse rounded-lg bg-surface-2", className)} />;
}

export function Spinner({ label }: { label?: string }) {
  const t = useT();
  return (
    <div role="status" className="flex items-center justify-center gap-2 py-10 text-fg-3">
      <Loader2 className="size-4 animate-spin" aria-hidden />
      <span>{label ?? t.common.loading}</span>
    </div>
  );
}

/** Uniform loading / error / empty handling for a useAsync result. */
export function AsyncView<T>({ state, children, skeleton, isEmpty, empty }: {
  state: AsyncState<T>;
  children: (data: T) => ReactNode;
  skeleton?: ReactNode;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
}) {
  const t = useT();
  if (state.data !== null) {
    if (isEmpty?.(state.data)) return <>{empty ?? <EmptyState title={t.common.noData} body={t.common.noDataBody} compact />}</>;
    return <>{children(state.data)}</>;
  }
  if (state.error) return <ErrorState error={state.error} onRetry={state.reload} compact />;
  return <>{skeleton ?? <Spinner />}</>;
}

// ------------------------------------------------------------------ Form controls

export function Field({ label, hint, children, className }: { label: string; hint?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <label className={cx("flex min-w-0 flex-col gap-1.5", className)}>
      <span className="text-sm font-medium text-fg-2">{label}</span>
      {children}
      {hint && <span className="text-sm text-fg-3">{hint}</span>}
    </label>
  );
}

const INPUT = "h-9.5 w-full min-w-0 rounded-lg border border-line-strong bg-surface-2 px-3 text-base text-fg placeholder:text-fg-3 transition-colors hover:border-fg-3 focus:border-focus focus:outline-none focus-visible:outline-2";

export function TextInput({ className, mono, ...rest }: InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }) {
  return <input className={cx(INPUT, mono && "font-mono text-sm", className)} spellCheck={false} {...rest} />;
}

export interface Option<V extends string> { value: V; label: string }

export function Select<V extends string>({ value, onChange, options, className, ...rest }: {
  value: V;
  onChange: (v: V) => void;
  options: readonly Option<V>[];
} & Omit<SelectHTMLAttributes<HTMLSelectElement>, "value" | "onChange">) {
  return (
    <span className={cx("relative inline-flex min-w-0", className)}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as V)}
        className={cx(INPUT, "appearance-none pr-9")}
        {...rest}
      >
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <ChevronDown className="pointer-events-none absolute top-1/2 right-2.5 size-4 -translate-y-1/2 text-fg-3" aria-hidden />
    </span>
  );
}

export function Segmented<V extends string>({ value, onChange, options, label, size = "md" }: {
  value: V;
  onChange: (v: V) => void;
  options: readonly Option<V>[];
  label: string;
  size?: "sm" | "md";
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-lg border border-line bg-surface-2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          onClick={() => onChange(o.value)}
          className={cx(
            "rounded-md px-3 font-medium whitespace-nowrap transition-colors",
            size === "sm" ? "h-7 text-sm" : "h-8 text-sm",
            o.value === value ? "bg-surface text-fg shadow-[0_0_0_1px_var(--line-strong)]" : "text-fg-3 hover:text-fg",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cx("relative h-6 w-11 shrink-0 rounded-full border transition-colors disabled:opacity-50", checked ? "border-accent bg-accent" : "border-line-strong bg-surface-3")}
    >
      <span className={cx("absolute top-0.5 size-4.5 rounded-full transition-[left,background-color]", checked ? "left-5.5 bg-accent-fg" : "left-0.5 bg-fg-2")} />
    </button>
  );
}

export function Checkbox({ checked, onChange, children, disabled }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="flex items-start gap-2.5">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 size-4.5 shrink-0 cursor-pointer rounded accent-(--accent)"
      />
      <label htmlFor={id} className="text-base text-fg-2">{children}</label>
    </div>
  );
}

export function Tabs<V extends string>({ value, onChange, tabs, label }: { value: V; onChange: (v: V) => void; tabs: readonly (Option<V> & { count?: number })[]; label: string }) {
  return (
    <div role="tablist" aria-label={label} className="flex gap-1 border-b border-line">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          role="tab"
          type="button"
          aria-selected={tab.value === value}
          onClick={() => onChange(tab.value)}
          className={cx(
            "-mb-px flex h-10 items-center gap-2 border-b-2 px-3 text-base font-medium whitespace-nowrap transition-colors",
            tab.value === value ? "border-accent text-fg" : "border-transparent text-fg-3 hover:text-fg",
          )}
        >
          {tab.label}
          {tab.count != null && <span className="tabular rounded-full bg-surface-3 px-1.5 text-xs text-fg-2">{tab.count}</span>}
        </button>
      ))}
    </div>
  );
}

// ------------------------------------------------------------------ Text helpers

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="inline-flex h-6 min-w-6 items-center justify-center rounded-md border border-line-strong bg-surface-2 px-1.5 text-xs text-fg-2">{children}</kbd>;
}

/** Untrusted command/path text: monospace, truncated, full value in the native tooltip. */
export function Mono({ text, className, wrap }: { text: string; className?: string; wrap?: boolean }) {
  return (
    <span title={text} className={cx("font-mono text-sm text-fg", wrap ? "break-all whitespace-pre-wrap" : "block truncate", className)}>
      {text}
    </span>
  );
}

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const t = useT();
  const [done, setDone] = useState(false);
  const Icon = done ? Check : Copy;
  return (
    <button
      type="button"
      aria-label={label ?? t.common.copy}
      title={done ? t.common.copied : (label ?? t.common.copy)}
      onClick={(e) => {
        e.stopPropagation();
        void copyText(text).then((ok) => {
          if (!ok) return;
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
      className={cx("inline-flex size-7 shrink-0 items-center justify-center rounded-md transition-colors hover:bg-surface-3", done ? "text-ok" : "text-fg-3 hover:text-fg")}
    >
      <Icon className="size-3.5" aria-hidden />
    </button>
  );
}

export function CodeBlock({ text, maxHeight = 320, wrap = true, label, className }: { text: string; maxHeight?: number; wrap?: boolean; label?: string; className?: string }) {
  return (
    <div className={cx("group relative rounded-lg border border-line bg-bg-2", className)}>
      {label && <div className="eyebrow border-b border-line px-3 py-1.5">{label}</div>}
      <div className="absolute top-1 right-1 opacity-70 group-hover:opacity-100"><CopyButton text={text} /></div>
      <pre
        tabIndex={0}
        style={{ maxHeight }}
        className={cx("overflow-auto px-3 py-2.5 pr-9 font-mono text-sm leading-relaxed text-fg", wrap ? "break-all whitespace-pre-wrap" : "whitespace-pre")}
      >
        {text}
      </pre>
    </div>
  );
}

/** Label/value rows for detail views. */
export function DefList({ items, className }: { items: { label: string; value: ReactNode }[]; className?: string }) {
  return (
    <dl className={cx("grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-2 text-base", className)}>
      {items.map((it) => (
        <div key={it.label} className="contents">
          <dt className="text-fg-3">{it.label}</dt>
          <dd className="min-w-0 text-fg">{it.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Meter({ value, max, tone = "var(--accent-2)", label }: { value: number; max: number; tone?: string; label?: string }) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div role="img" aria-label={label} className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
      <div className="h-full rounded-full transition-[width] duration-300" style={{ width: `${pct}%`, background: tone }} />
    </div>
  );
}
