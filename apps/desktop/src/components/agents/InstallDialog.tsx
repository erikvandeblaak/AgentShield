import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, FolderArchive, OctagonAlert } from "lucide-react";
import { Dialog } from "../overlay";
import { Badge, Button, Callout, Checkbox, ErrorState, Mono, Spinner, Switch, cx } from "../ui";
import { diffLines, type DiffLine } from "./diff";
import { fmt, useT } from "../../i18n";
import { backend } from "../../lib/backend";
import { errorMessage } from "../../lib/format";
import type { AgentInfo, InstallPlan, InstallResult } from "../../lib/types";

function DiffPane({ title, lines, side }: { title: string; lines: DiffLine[]; side: "before" | "after" }) {
  const hide = side === "before" ? "added" : "removed";
  const mark = side === "before" ? "removed" : "added";
  const tone = side === "before" ? "var(--danger)" : "var(--ok)";
  return (
    <div className="min-w-0 rounded-lg border border-line bg-bg-2">
      <div className="eyebrow border-b border-line px-3 py-1.5">{title}</div>
      <pre tabIndex={0} className="max-h-72 overflow-auto py-2 font-mono text-sm leading-relaxed text-fg" aria-label={title}>
        {lines.filter((l) => l.kind !== hide).map((l, i) => (
          <div
            key={i}
            className={cx("flex min-w-max px-3", l.kind === mark && "font-medium")}
            style={l.kind === mark ? { background: `color-mix(in srgb, ${tone} 14%, transparent)` } : undefined}
          >
            <span className="w-4 shrink-0 select-none" style={{ color: tone }} aria-hidden>{l.kind === mark ? (side === "before" ? "−" : "+") : " "}</span>
            <span className="whitespace-pre">{l.text || " "}</span>
          </div>
        ))}
      </pre>
    </div>
  );
}

/**
 * Install / repair flow: preview → explicit consent → install. Nothing is written before the
 * consent checkbox is ticked and "Apply changes" is pressed. No option is pre-selected.
 */
export function InstallDialog({ agent, repair, onClose, onDone }: { agent: AgentInfo; repair: boolean; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const d = t.agents.dialog;
  const [failClosed, setFailClosed] = useState(false);
  const [plan, setPlan] = useState<InstallPlan | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<InstallResult | null>(null);
  const [installError, setInstallError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setPlanError(null);
    setConsent(false); // a changed plan needs fresh consent
    backend.installPreview(agent.id, failClosed)
      .then((p) => !cancelled && setPlan(p))
      .catch((e: unknown) => !cancelled && setPlanError(errorMessage(e)));
    return () => {
      cancelled = true;
    };
  }, [agent.id, failClosed, attempt]);

  const lines = useMemo(() => (plan ? diffLines(plan.before, plan.after) : []), [plan]);

  const apply = async () => {
    setBusy(true);
    setInstallError(null);
    try {
      setResult(await backend.install(agent.id, failClosed));
      onDone();
    } catch (e) {
      setInstallError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const title = fmt(repair ? d.repairTitle : d.installTitle, { agent: agent.name });

  if (result) {
    return (
      <Dialog open onClose={onClose} title={title} width={640} tone={result.ok ? "var(--ok)" : "var(--danger)"} footer={<Button variant="primary" onClick={onClose} data-autofocus>{t.common.done}</Button>}>
        <div className="space-y-4 pb-2">
          <div className="flex items-center gap-3">
            {result.ok ? <CheckCircle2 className="size-6 text-ok" aria-hidden /> : <OctagonAlert className="size-6 text-danger" aria-hidden />}
            <span className="text-lg font-semibold text-fg">{result.ok ? d.resultOk : d.resultFailed}</span>
          </div>
          <p className="text-base text-fg-2">{result.message}</p>
          <dl className="space-y-3 text-base">
            <div>
              <dt className="eyebrow mb-1">{d.verification}</dt>
              <dd><Badge tone={result.verified ? "var(--ok)" : "var(--warn)"} dot>{result.verified ? d.verifiedYes : d.verifiedNo}</Badge></dd>
            </div>
            <div>
              <dt className="eyebrow mb-1">{d.backupPath}</dt>
              <dd>{result.backup_path ? <Mono text={result.backup_path} wrap /> : <span className="text-fg-3">{d.noBackup}</span>}</dd>
            </div>
          </dl>
          {result.problems.length > 0 && (
            <Callout tone="warn" title={t.agents.problems}>
              <ul className="mt-1 list-disc space-y-1 pl-4.5">{result.problems.map((p) => <li key={p}>{p}</li>)}</ul>
            </Callout>
          )}
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={title}
      width={980}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} data-autofocus>{t.common.cancel}</Button>
          <Button variant={failClosed ? "danger" : "primary"} disabled={!plan || !consent} loading={busy} onClick={() => void apply()}>{d.installNow}</Button>
        </>
      }
    >
      <div className="space-y-5 pb-2">
        <p>{d.intro}</p>
        {planError ? (
          <ErrorState error={`${d.previewFailed}: ${planError}`} onRetry={() => setAttempt((n) => n + 1)} compact />
        ) : !plan ? (
          <Spinner label={d.loadingPreview} />
        ) : (
          <>
            {plan.already_installed && <Callout tone="info">{d.alreadyInstalled}</Callout>}
            <section>
              <h3 className="eyebrow mb-2">{d.changes}</h3>
              {plan.changes.length === 0 ? <p className="text-fg-3">{d.noChanges}</p> : (
                <ul className="space-y-1.5">
                  {plan.changes.map((c) => (
                    <li key={c} className="flex gap-2.5"><span className="mt-2 size-1.5 shrink-0 rounded-full bg-accent-2" aria-hidden />{c}</li>
                  ))}
                </ul>
              )}
            </section>
            <section>
              <div className="mb-2 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                <h3 className="eyebrow">{d.settingsFile}</h3>
                <code className="min-w-0 truncate text-sm text-fg" title={plan.settings_path}>{plan.settings_path}</code>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <DiffPane title={d.before} lines={lines} side="before" />
                <DiffPane title={d.after} lines={lines} side="after" />
              </div>
              <p className="mt-2 text-sm text-fg-3">{d.diffLegend}</p>
              <p className="mt-2 flex items-center gap-2 text-sm text-fg-2">
                <FolderArchive className="size-4 shrink-0 text-fg-3" aria-hidden />
                <span>{d.backupDir}</span>
                <code className="min-w-0 truncate text-fg" title={plan.backup_dir}>{plan.backup_dir}</code>
              </p>
            </section>
          </>
        )}

        <section className="rounded-xl border border-line bg-surface-2 p-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="text-base font-semibold text-fg">{d.failClosedLabel}</div>
              <div className="text-sm text-fg-3">{failClosed ? t.agents.failClosedHint : d.failClosedOff}</div>
            </div>
            <Switch checked={failClosed} onChange={setFailClosed} label={d.failClosedLabel} />
          </div>
          {failClosed && <Callout tone="danger" title={d.failClosedWarnTitle} className="mt-3">{d.failClosedWarnBody}</Callout>}
        </section>

        {installError && <Callout tone="danger" title={d.resultFailed}>{installError}</Callout>}
        <Checkbox checked={consent} onChange={setConsent} disabled={!plan}>{d.consent}</Checkbox>
      </div>
    </Dialog>
  );
}
