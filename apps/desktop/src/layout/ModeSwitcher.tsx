import { useEffect, useRef, useState, type CSSProperties } from "react";
import { Check, ChevronDown, ShieldOff } from "lucide-react";
import { MODE_ICON, ModeBadge } from "../components/badges";
import { Dialog } from "../components/overlay";
import { Button, Callout, Checkbox, cx } from "../components/ui";
import { fmt, useT, type Dict } from "../i18n";
import { errorMessage } from "../lib/format";
import { useApp } from "../store/app";
import { MODE_VAR, v } from "../theme/palette";
import type { Mode } from "../lib/types";

const MODES: Mode[] = ["monitor", "shadow", "interactive", "enforce", "lockdown"];

export function consequences(t: Dict, mode: Mode): string[] {
  const d = t.shell.modeDialog;
  switch (mode) {
    case "monitor": return [d.monitor1, d.monitor2];
    case "shadow": return [d.shadow1, d.shadow2];
    case "interactive": return [d.interactive1, d.interactive2, d.interactive3];
    case "enforce": return [d.enforce1, d.enforce2, d.enforce3, d.enforce4];
    case "lockdown": return [d.lockdown1, d.lockdown2];
  }
}

/** Confirmation with consequences. Enforce/Lockdown require an explicit acknowledgement. */
export function ModeChangeDialog({ target, onClose }: { target: Mode | null; onClose: () => void }) {
  const t = useT();
  const d = t.shell.modeDialog;
  const setMode = useApp((s) => s.setMode);
  const toast = useApp((s) => s.toast);
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => setAck(false), [target]);
  if (!target) return null;
  const label = t.enums.mode[target].label;
  const strict = target === "enforce" || target === "lockdown";
  const apply = async () => {
    setBusy(true);
    try {
      await setMode(target);
      onClose();
    } catch (e) {
      toast("danger", `${d.failed}: ${errorMessage(e)}`);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open
      onClose={onClose}
      width={600}
      tone={v(MODE_VAR[target])}
      title={fmt(d.title, { mode: label })}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} data-autofocus>{t.common.cancel}</Button>
          <Button variant={target === "lockdown" ? "danger" : "primary"} disabled={strict && !ack} loading={busy} onClick={() => void apply()}>
            {fmt(d.switchTo, { mode: label })}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <ModeBadge mode={target} size="lg" />
          <span className="text-base text-fg-2">{t.enums.mode[target].tagline}</span>
        </div>
        <div>
          <div className="eyebrow mb-2">{d.consequences}</div>
          <ul className="space-y-2">
            {consequences(t, target).map((line) => (
              <li key={line} className="flex gap-2.5 text-base text-fg-2">
                <span className="mt-2 size-1.5 shrink-0 rounded-full" style={{ background: v(MODE_VAR[target]) }} aria-hidden />
                {line}
              </li>
            ))}
          </ul>
        </div>
        {target === "lockdown" && (
          <Callout tone="warn" icon={ShieldOff} title={d.outsideTitle}>
            <ul className="mt-1.5 list-disc space-y-1 pl-4.5">
              {[d.outside1, d.outside2, d.outside3, d.outside4, d.outside5].map((line) => <li key={line}>{line}</li>)}
            </ul>
          </Callout>
        )}
        {strict && <Checkbox checked={ack} onChange={setAck}>{d.ack}</Checkbox>}
      </div>
    </Dialog>
  );
}

/** Permanent mode indicator in the top bar + mode menu. */
export function ModeSwitcher() {
  const t = useT();
  const mode = useApp((s) => s.status?.mode);
  const setMode = useApp((s) => s.setMode);
  const toast = useApp((s) => s.toast);
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState<Mode | null>(null);
  const wrap = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (!mode) return null;

  const choose = (m: Mode) => {
    setOpen(false);
    if (m === mode) return;
    if (m === "monitor" || m === "shadow") {
      setMode(m).catch((e: unknown) => toast("danger", `${t.shell.modeDialog.failed}: ${errorMessage(e)}`));
    } else setTarget(m);
  };

  return (
    <div ref={wrap} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`${t.shell.topbar.currentMode}: ${t.enums.mode[mode].banner} — ${t.enums.mode[mode].tagline}. ${t.shell.topbar.changeMode}`}
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 rounded-lg"
      >
        <ModeBadge mode={mode} size="lg" showTagline />
        <ChevronDown className={cx("size-4 text-fg-3 transition-transform", open && "rotate-180")} aria-hidden />
      </button>
      {open && (
        <div role="menu" aria-label={t.shell.topbar.changeMode} className="absolute top-full left-0 z-30 mt-2 w-108 animate-rise rounded-xl border border-line-strong bg-surface p-1.5 shadow-pop">
          {MODES.map((m) => {
            const Icon = MODE_ICON[m];
            const active = m === mode;
            return (
              <button
                key={m}
                type="button"
                role="menuitemradio"
                aria-checked={active}
                onClick={() => choose(m)}
                style={{ "--tone": v(MODE_VAR[m]) } as CSSProperties}
                className={cx("flex w-full items-start gap-3 rounded-lg px-3 py-2.5 text-left transition-colors hover:bg-surface-2", active && "bg-surface-2")}
              >
                <span className="tone mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg"><Icon className="size-4" aria-hidden /></span>
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2 text-base font-semibold text-fg">
                    {t.enums.mode[m].label}
                    {active && <span className="text-xs font-medium text-(--tone)">{t.shell.modeDialog.current}</span>}
                  </span>
                  <span className="mt-0.5 block text-sm text-fg-3">{t.enums.mode[m].description}</span>
                </span>
                {active && <Check className="mt-1 size-4 shrink-0 text-(--tone)" aria-hidden />}
              </button>
            );
          })}
        </div>
      )}
      <ModeChangeDialog target={target} onClose={() => setTarget(null)} />
    </div>
  );
}
