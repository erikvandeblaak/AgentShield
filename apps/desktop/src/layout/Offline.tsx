import { useState } from "react";
import { FlaskConical, MonitorOff, Play, PlugZap } from "lucide-react";
import { LogoMark } from "../components/Logo";
import { Button, cx } from "../components/ui";
import { useT } from "../i18n";
import { backend, isTauri } from "../lib/backend";
import { errorMessage } from "../lib/format";
import { useApp } from "../store/app";

/**
 * Shown instead of any data view while the daemon is unreachable. We never render empty charts that
 * could be mistaken for "zero events". Outside Tauri (plain browser) Demo Mode is offered up front.
 */
export function OfflineScreen() {
  const t = useT();
  const o = t.shell.offline;
  const statusError = useApp((s) => s.statusError);
  const setStatus = useApp((s) => s.setStatus);
  const setDemo = useApp((s) => s.setDemo);
  const [busy, setBusy] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const inTauri = isTauri();

  const start = async () => {
    setBusy(true);
    setStartError(null);
    try {
      setStatus(await backend.startDaemon());
      useApp.getState().bumpEpoch();
      void useApp.getState().loadConfig();
    } catch (e) {
      setStartError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const Icon = inTauri ? PlugZap : MonitorOff;
  return (
    <div className="flex min-h-full items-center justify-center p-8">
      <div className="w-full max-w-2xl animate-rise">
        <div className="relative overflow-hidden rounded-2xl border border-line bg-surface p-8 shadow-card">
          <div aria-hidden className="pointer-events-none absolute -top-24 -right-16 opacity-[0.06]"><LogoMark size={300} mono /></div>
          <div className={cx("flex size-12 items-center justify-center rounded-xl border", inTauri ? "border-danger/40 bg-danger/10 text-danger" : "border-line-strong bg-surface-2 text-fg-2")}>
            <Icon className="size-6" aria-hidden />
          </div>
          <h1 className="mt-5 text-3xl font-semibold tracking-tight text-fg">{inTauri ? o.title : o.browserTitle}</h1>
          <p className="mt-2 max-w-xl text-lg text-fg-2">{inTauri ? o.body : o.browserBody}</p>

          <div className="mt-6 flex flex-wrap items-center gap-3">
            {inTauri ? (
              <>
                <Button variant="primary" icon={Play} loading={busy} onClick={() => void start()}>{busy ? o.starting : o.start}</Button>
                <span className="flex items-center gap-2 text-sm text-fg-3">
                  <span className="size-1.5 animate-pulse rounded-full bg-fg-3" aria-hidden />
                  {o.retrying}
                </span>
              </>
            ) : (
              <Button variant="primary" icon={FlaskConical} onClick={() => setDemo(true)}>{o.demoCta}</Button>
            )}
          </div>

          {(startError ?? (inTauri ? statusError : null)) && (
            <div className="mt-5">
              <div className="eyebrow mb-1">{o.lastError}</div>
              <pre role="alert" className="max-h-28 overflow-auto rounded-lg border border-line bg-bg-2 px-3 py-2 font-mono text-sm whitespace-pre-wrap text-fg-2">{startError ?? statusError}</pre>
            </div>
          )}

          {inTauri && (
            <div className="mt-6 border-t border-line pt-5">
              <div className="eyebrow mb-2">{o.whatHappens}</div>
              <ul className="space-y-1.5 text-base text-fg-2">
                {[o.whatHappens1, o.whatHappens2, o.whatHappens3].map((line) => (
                  <li key={line} className="flex gap-2.5"><span className="mt-2 size-1.5 shrink-0 rounded-full bg-fg-3" aria-hidden />{line}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="mt-4 flex items-center justify-between gap-4 px-2 text-sm text-fg-3">
          <span>{o.demoHint}</span>
          {inTauri && (
            <button type="button" onClick={() => setDemo(true)} className="inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 font-medium text-fg-2 underline-offset-4 hover:text-fg hover:underline">
              <FlaskConical className="size-4" aria-hidden />
              {o.demoCta}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
