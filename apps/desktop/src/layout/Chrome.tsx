import { CheckCircle2, FlaskConical, Info, OctagonAlert, TriangleAlert, X } from "lucide-react";
import { LogoMark, Wordmark } from "../components/Logo";
import { Dialog } from "../components/overlay";
import { Kbd } from "../components/ui";
import { useT } from "../i18n";
import { useApp, type Toast } from "../store/app";
import { NAV } from "./nav";

/** Persistent, unmistakable Demo Mode banner. Rendered above everything while demo is active. */
export function DemoBanner() {
  const t = useT();
  const setDemo = useApp((s) => s.setDemo);
  return (
    <div role="status" data-testid="demo-banner" className="flex h-9 shrink-0 items-center justify-center gap-3 bg-[#f5b942] px-4 text-sm text-[#231a00]">
      <FlaskConical className="size-4 shrink-0" aria-hidden />
      <strong className="font-bold tracking-wide">{t.shell.demo.banner}</strong>
      <span className="hidden lg:inline">{t.shell.demo.bannerDetail}</span>
      <button type="button" onClick={() => setDemo(false)} className="ml-2 rounded-md border border-[#231a00]/40 px-2 py-0.5 font-semibold hover:bg-[#231a00]/10 focus-visible:outline-[#231a00]">
        {t.shell.demo.exit}
      </button>
    </div>
  );
}

/** Repeating diagonal watermark so screenshots of Demo Mode can never pass for real monitoring. */
export function DemoWatermark() {
  const t = useT();
  const word = t.shell.demo.watermark;
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-[55] overflow-hidden select-none">
      <div className="absolute -inset-1/4 flex rotate-[-24deg] flex-wrap content-center justify-center gap-x-40 gap-y-36 opacity-[0.032]">
        {Array.from({ length: 40 }, (_, i) => (
          <span key={i} className="text-6xl font-black tracking-[0.3em] text-fg">{word}</span>
        ))}
      </div>
      <div className="absolute right-4 bottom-3 rounded-md border border-[#f5b942]/50 bg-[#f5b942]/15 px-2 py-1 text-xs font-bold tracking-widest text-warn">
        {t.shell.demo.watermarkDetail}
      </div>
    </div>
  );
}

const TOAST_ICON = { ok: CheckCircle2, warn: TriangleAlert, danger: OctagonAlert, info: Info } as const;
const TOAST_TONE = { ok: "var(--ok)", warn: "var(--warn)", danger: "var(--danger)", info: "var(--info)" } as const;

export function Toasts() {
  const t = useT();
  const toasts = useApp((s) => s.toasts);
  const dismiss = useApp((s) => s.dismissToast);
  return (
    <div className="pointer-events-none fixed right-5 bottom-12 z-[60] flex w-96 flex-col gap-2" aria-live="polite">
      {toasts.map((toast: Toast) => {
        const Icon = TOAST_ICON[toast.tone];
        return (
          <div key={toast.id} role={toast.tone === "danger" ? "alert" : "status"} className="pointer-events-auto flex animate-rise items-start gap-3 rounded-xl border border-line-strong bg-surface-3 px-4 py-3 shadow-pop">
            <Icon className="mt-0.5 size-4.5 shrink-0" style={{ color: TOAST_TONE[toast.tone] }} aria-hidden />
            <div className="min-w-0 flex-1 text-base break-words text-fg">{toast.text}</div>
            <button type="button" aria-label={t.common.close} onClick={() => dismiss(toast.id)} className="rounded text-fg-3 hover:text-fg">
              <X className="size-4" aria-hidden />
            </button>
          </div>
        );
      })}
    </div>
  );
}

export function Splash() {
  const t = useT();
  return (
    <div className="app-bg flex h-full flex-col items-center justify-center gap-5" role="status" aria-label={t.common.loading}>
      <LogoMark size={84} scanning className="animate-fade-in" />
      <Wordmark className="text-3xl!" />
      <div className="text-base text-fg-3">{t.common.subtitle}</div>
      <div className="mt-2 h-0.5 w-40 overflow-hidden rounded-full bg-surface-3">
        <div className="h-full w-1/3 animate-pulse rounded-full bg-accent-2" />
      </div>
      <div className="absolute bottom-6 text-sm text-fg-3">{t.common.developedBy} · {t.common.website}</div>
    </div>
  );
}

export function ShortcutsDialog() {
  const t = useT();
  const s = t.shell.shortcuts;
  const open = useApp((st) => st.shortcutsOpen);
  const setOpen = useApp((st) => st.setShortcutsOpen);
  return (
    <Dialog open={open} onClose={() => setOpen(false)} title={s.title} width={680}>
      <div className="grid grid-cols-2 gap-x-10 gap-y-5 pb-4">
        <div>
          <div className="eyebrow mb-2">{s.general}</div>
          <ul className="space-y-2">
            <li className="flex items-center justify-between gap-3"><span>{s.focusSearch}</span><Kbd>/</Kbd></li>
            <li className="flex items-center justify-between gap-3"><span>{s.closePanel}</span><Kbd>Esc</Kbd></li>
            <li className="flex items-center justify-between gap-3"><span>{s.showHelp}</span><Kbd>?</Kbd></li>
          </ul>
        </div>
        {NAV.map((group) => (
          <div key={group.label}>
            <div className="eyebrow mb-2">{s.goTo} · {t.shell.nav[group.label]}</div>
            <ul className="space-y-2">
              {group.items.map((item) => (
                <li key={item.id} className="flex items-center justify-between gap-3">
                  <span>{t.shell.nav[item.id]}</span>
                  <span className="flex items-center gap-1.5"><Kbd>g</Kbd><span className="text-sm text-fg-3">{s.then}</span><Kbd>{item.key}</Kbd></span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Dialog>
  );
}
