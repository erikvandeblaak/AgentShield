import { useEffect, useId, useRef, useState, type ReactNode, type RefObject } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { Button, IconButton, TextInput, cx } from "./ui";
import { useT } from "../i18n";

// Esc closes only the top-most overlay.
const escStack: (() => void)[] = [];
if (typeof window !== "undefined") {
  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || escStack.length === 0) return;
    e.stopPropagation();
    escStack[escStack.length - 1]?.();
  });
}

export function overlayOpen(): boolean {
  return escStack.length > 0;
}

function useOverlay(open: boolean, onClose: () => void, ref: RefObject<HTMLElement | null>, trap: boolean): void {
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const handler = () => closeRef.current();
    escStack.push(handler);
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const node = ref.current;
    const focusable = () => Array.from(node?.querySelectorAll<HTMLElement>('button:not([disabled]),[href],input:not([disabled]),select,textarea,[tabindex]:not([tabindex="-1"])') ?? []);
    (node?.querySelector<HTMLElement>("[data-autofocus]") ?? node)?.focus({ preventScroll: true });
    const onKey = (e: KeyboardEvent) => {
      if (!trap || e.key !== "Tab") return;
      const items = focusable();
      const first = items[0], last = items[items.length - 1];
      if (!first || !last) return;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    node?.addEventListener("keydown", onKey);
    return () => {
      const i = escStack.lastIndexOf(handler);
      if (i >= 0) escStack.splice(i, 1);
      node?.removeEventListener("keydown", onKey);
      previous?.focus({ preventScroll: true });
    };
  }, [open, ref, trap]);
}

// ------------------------------------------------------------------ Side panel (non-modal)

export function SidePanel({ open, onClose, title, subtitle, children, width = 620, headerExtra }: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  width?: number;
  headerExtra?: ReactNode;
}) {
  const t = useT();
  const ref = useRef<HTMLElement>(null);
  const titleId = useId();
  useOverlay(open, onClose, ref, false);
  if (!open) return null;
  return createPortal(
    <aside
      ref={ref}
      role="dialog"
      aria-modal="false"
      aria-labelledby={titleId}
      tabIndex={-1}
      style={{ width: `min(${width}px, calc(100vw - 80px))` }}
      className="fixed top-(--banner-h,0px) right-0 bottom-0 z-40 flex animate-slide-in flex-col border-l border-line-strong bg-surface shadow-pop outline-none"
    >
      <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-xl font-semibold text-fg">{title}</h2>
          {subtitle && <div className="mt-1 text-sm text-fg-3">{subtitle}</div>}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {headerExtra}
          <IconButton icon={X} label={t.common.close} onClick={onClose} />
        </div>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
    </aside>,
    document.body,
  );
}

// ------------------------------------------------------------------ Modal dialog

export function Dialog({ open, onClose, title, children, footer, width = 560, tone }: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
  /** CSS colour for the top accent line. */
  tone?: string;
}) {
  const t = useT();
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useOverlay(open, onClose, ref, true);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-x-0 top-(--banner-h,0px) bottom-0 z-50 flex animate-fade-in items-center justify-center bg-black/55 p-6 backdrop-blur-[2px]" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        style={{ width: `min(${width}px, 100%)`, ...(tone ? { boxShadow: `inset 0 3px 0 0 ${tone}, var(--shadow-pop)` } : {}) }}
        className="flex max-h-full animate-rise flex-col rounded-2xl border border-line-strong bg-surface shadow-pop outline-none"
      >
        <header className="flex items-start justify-between gap-3 px-6 pt-5 pb-2">
          <h2 id={titleId} className="text-2xl font-semibold text-fg">{title}</h2>
          <IconButton icon={X} label={t.common.close} onClick={onClose} className="-mt-1 -mr-2" />
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-2 text-base text-fg-2">{children}</div>
        {footer && <footer className="flex flex-wrap items-center justify-end gap-2 px-6 pt-3 pb-5">{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

export function ConfirmDialog({ open, title, children, confirmLabel, cancelLabel, danger, busy, requireText, requireTextLabel, onConfirm, onCancel }: {
  open: boolean;
  title: ReactNode;
  children?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  danger?: boolean;
  busy?: boolean;
  /** When set, the user must type this exact text before the confirm button is enabled. */
  requireText?: string;
  requireTextLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [typed, setTyped] = useState("");
  useEffect(() => {
    if (!open) setTyped("");
  }, [open]);
  const ok = !requireText || typed.trim() === requireText;
  return (
    <Dialog
      open={open}
      onClose={onCancel}
      title={title}
      tone={danger ? "var(--danger)" : undefined}
      footer={
        <>
          <Button variant="ghost" onClick={onCancel} data-autofocus>{cancelLabel ?? t.common.cancel}</Button>
          <Button variant={danger ? "danger" : "primary"} disabled={!ok} loading={busy} onClick={onConfirm}>{confirmLabel}</Button>
        </>
      }
    >
      <div className={cx("space-y-3")}>
        {children}
        {requireText && (
          <label className="block space-y-1.5">
            <span className="text-sm text-fg-2">{requireTextLabel}</span>
            <TextInput value={typed} onChange={(e) => setTyped(e.target.value)} mono aria-label={requireTextLabel} />
          </label>
        )}
      </div>
    </Dialog>
  );
}
