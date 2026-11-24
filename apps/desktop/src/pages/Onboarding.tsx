import { useState, type ReactNode } from "react";
import {
  ArrowLeft, ArrowRight, Check, CircleCheck, CircleX, Cloud, Eye, FlaskConical, KeyRound, LayoutDashboard, Lightbulb, RefreshCw,
  ShieldOff, SlidersHorizontal, UserX, type LucideIcon,
} from "lucide-react";
import { ActualBadge, CapabilityBadge, ModeBadge } from "../components/badges";
import { LogoMark } from "../components/Logo";
import { Dialog } from "../components/overlay";
import { Badge, Button, Callout, Checkbox, CodeBlock, DefList, ErrorState, Spinner, cx } from "../components/ui";
import { fmt, useT, type Dict } from "../i18n";
import { backend } from "../lib/backend";
import { errorMessage } from "../lib/format";
import { useAsync } from "../lib/hooks";
import { navigate } from "../lib/router";
import { useApp } from "../store/app";
import type { InstallResult, SelfTestResult } from "../lib/types";

const ONBOARDED_KEY = "agentshield.onboarded"; // same key as App.tsx (string literal avoids a circular import)
const AGENT_ID = "claude-code";
const TOTAL = 10;

type StepKey = Extract<keyof Dict["onboarding"], `step${string}`>;
const STEP_KEYS: StepKey[] = [
  "stepWelcome", "stepPrivacy", "stepDetect", "stepCapabilities", "stepPreview", "stepConsent", "stepMode", "stepTest", "stepVerify", "stepFinish",
];

function markOnboarded(): void {
  try {
    localStorage.setItem(ONBOARDED_KEY, "1");
  } catch {
    /* storage unavailable */
  }
}

function StepHeading({ title, body }: { title: string; body?: ReactNode }) {
  return (
    <div className="mb-5">
      <h3 className="text-2xl font-semibold tracking-tight text-fg">{title}</h3>
      {body && <p className="mt-1.5 max-w-2xl text-base text-fg-2">{body}</p>}
    </div>
  );
}

function Feature({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <div className="flex gap-3 rounded-xl border border-line bg-surface-2 p-4">
      <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-line bg-surface text-accent-2"><Icon className="size-4.5" aria-hidden /></div>
      <div className="min-w-0">
        <div className="text-base font-semibold text-fg">{title}</div>
        <p className="mt-0.5 text-sm text-fg-2">{body}</p>
      </div>
    </div>
  );
}

function StatusLine({ ok, children }: { ok: boolean; children: ReactNode }) {
  const Icon = ok ? CircleCheck : CircleX;
  return (
    <li className="flex items-center gap-2.5 text-base text-fg">
      <Icon className={cx("size-5 shrink-0", ok ? "text-ok" : "text-fg-3")} aria-hidden />
      {children}
    </li>
  );
}

export default function OnboardingWizard() {
  const t = useT();
  const o = t.onboarding;
  const mode = useApp((s) => s.status?.mode);
  const { setOnboardingOpen, setMode, openEventById } = useApp.getState();

  const [step, setStep] = useState(0);
  const [consent, setConsent] = useState(false); // never pre-checked
  const [installing, setInstalling] = useState(false);
  const [installResult, setInstallResult] = useState<InstallResult | null>(null);
  const [installError, setInstallError] = useState<string | null>(null);
  const [skippedInstall, setSkippedInstall] = useState(false);
  const [modeBusy, setModeBusy] = useState(false);
  const [modeError, setModeError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<SelfTestResult | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  const agents = useAsync(() => backend.agents(), [], { enabled: step >= 2 });
  const plan = useAsync(() => backend.installPreview(AGENT_ID, false), [], { enabled: step >= 4 });

  const claude = agents.data?.find((a) => a.id === AGENT_ID) ?? null;
  const others = agents.data?.filter((a) => a.id !== AGENT_ID) ?? [];
  const alreadyInstalled = !!(plan.data?.already_installed ?? claude?.integration?.installed);
  const installed = alreadyInstalled || !!installResult?.ok;

  const close = () => setOnboardingOpen(false);
  const skipSetup = () => {
    markOnboarded();
    close();
  };
  const finish = () => {
    markOnboarded();
    close();
    navigate("overview");
  };

  const install = async () => {
    if (!consent) return;
    setInstalling(true);
    setInstallError(null);
    try {
      const res = await backend.install(AGENT_ID, false);
      setInstallResult(res);
      setSkippedInstall(false);
      if (!res.ok) setInstallError(res.message);
      else {
        agents.reload();
        plan.reload();
      }
    } catch (e) {
      setInstallError(errorMessage(e));
    } finally {
      setInstalling(false);
    }
  };
  const activateMonitor = async () => {
    setModeBusy(true);
    setModeError(null);
    try {
      await setMode("monitor");
    } catch (e) {
      setModeError(errorMessage(e));
    } finally {
      setModeBusy(false);
    }
  };
  const runTest = async () => {
    setTesting(true);
    setTestError(null);
    try {
      setTest(await backend.selfTest());
    } catch (e) {
      setTest(null);
      setTestError(errorMessage(e));
    } finally {
      setTesting(false);
    }
  };
  const viewEvent = (id: number) => {
    markOnboarded();
    close();
    navigate("live");
    setTimeout(() => void openEventById(id), 200);
  };

  // Step 6 needs an explicit choice: install (with consent) or skip.
  const nextBlocked = step === 5 && !installed && !skippedInstall;

  const body: ReactNode = (() => {
    switch (step) {
      case 0:
        return (
          <div className="flex h-full flex-col items-start justify-center">
            <LogoMark size={72} />
            <h3 className="mt-5 text-3xl font-semibold tracking-tight text-fg">{o.welcomeTitle}</h3>
            <p className="mt-1 text-lg font-medium text-accent-2">{t.common.tagline}</p>
            <p className="mt-3 max-w-2xl text-base text-fg-2">{o.welcomeBody}</p>
            <ul className="mt-5 space-y-2.5">
              {[o.welcomePoint1, o.welcomePoint2, o.welcomePoint3].map((line) => (
                <li key={line} className="flex gap-2.5 text-base text-fg-2"><Check className="mt-0.5 size-4.5 shrink-0 text-ok" aria-hidden />{line}</li>
              ))}
            </ul>
            <p className="mt-6 text-sm text-fg-3">{o.welcomeNote}</p>
          </div>
        );
      case 1:
        return (
          <>
            <StepHeading title={o.privacyTitle} body={o.privacyBody} />
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <Feature icon={Cloud} title={o.privacy1Title} body={o.privacy1Body} />
              <Feature icon={UserX} title={o.privacy2Title} body={o.privacy2Body} />
              <Feature icon={KeyRound} title={o.privacy3Title} body={o.privacy3Body} />
              <Feature icon={SlidersHorizontal} title={o.privacy4Title} body={o.privacy4Body} />
            </div>
          </>
        );
      case 2:
        return (
          <>
            <StepHeading title={o.detectTitle} body={o.detectBody} />
            {agents.data === null ? (agents.error ? <ErrorState compact error={agents.error} onRetry={agents.reload} /> : <Spinner label={o.detecting} />) : (
              <>
                {agents.data.length === 0 && <p className="text-base text-fg-3">{o.noAgents}</p>}
                <ul className="space-y-2.5">
                  {agents.data.map((a) => (
                    <li key={a.id} className="flex items-center gap-4 rounded-xl border border-line bg-surface-2 px-4 py-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-lg font-semibold text-fg">{a.name}</span>
                          {a.version && <code className="font-mono text-sm text-fg-3">{a.version}</code>}
                        </div>
                        {a.executable && <code className="mt-0.5 block truncate font-mono text-sm text-fg-3" title={a.executable}>{a.executable}</code>}
                        {a.supported && a.detected && (
                          <div className="mt-1 text-sm text-fg-2">{a.integration?.installed ? o.integrationInstalled : o.integrationMissing}</div>
                        )}
                      </div>
                      <div className="flex shrink-0 flex-col items-end gap-1.5">
                        <Badge tone={a.detected ? "var(--ok)" : "var(--fg-3)"} dot>{a.detected ? o.detected : o.notDetected}</Badge>
                        <Badge tone={a.supported ? "var(--info)" : "var(--fg-3)"}>{a.supported ? o.supported : o.notSupported}</Badge>
                      </div>
                    </li>
                  ))}
                </ul>
                {!claude?.detected && <Callout tone="warn" className="mt-4">{o.claudeMissing}</Callout>}
                <Button size="sm" variant="ghost" icon={RefreshCw} className="mt-3 -ml-2" loading={agents.refreshing} onClick={agents.reload}>{o.redetect}</Button>
              </>
            )}
          </>
        );
      case 3:
        return (
          <>
            <StepHeading title={o.capTitle} body={o.capBody} />
            {agents.data === null ? (agents.error ? <ErrorState compact error={agents.error} onRetry={agents.reload} /> : <Spinner />) : (
              <>
                {claude && claude.capabilities.length > 0 ? (
                  <ul className="overflow-hidden rounded-xl border border-line">
                    {claude.capabilities.map((c) => (
                      <li key={c.capability} className="grid grid-cols-[minmax(0,15rem)_9rem_minmax(0,1fr)] items-start gap-4 border-b border-line/70 bg-surface-2 px-4 py-2.5 last:border-b-0">
                        <span className="text-base font-medium text-fg">{c.capability}</span>
                        <span><CapabilityBadge state={c.status} /></span>
                        <span className="text-sm text-fg-2">{c.reason}</span>
                      </li>
                    ))}
                  </ul>
                ) : <p className="text-base text-fg-3">{o.capNone}</p>}
                {others.some((a) => !a.supported) && (
                  <Callout tone="neutral" icon={ShieldOff} title={o.capUnsupportedTitle} className="mt-4">
                    {o.capUnsupportedBody} <span className="font-medium text-fg">{others.filter((a) => !a.supported).map((a) => a.name).join(", ")}</span>
                  </Callout>
                )}
              </>
            )}
          </>
        );
      case 4:
        return (
          <>
            <StepHeading title={o.previewTitle} body={o.previewBody} />
            {plan.data === null ? (plan.error ? <ErrorState compact error={plan.error} onRetry={plan.reload} /> : <Spinner label={o.previewLoading} />) : (
              <>
                {plan.data.already_installed && <Callout tone="ok" className="mb-4">{o.alreadyInstalled}</Callout>}
                <DefList
                  items={[
                    { label: o.settingsFile, value: <code className="font-mono text-sm break-all">{plan.data.settings_path}</code> },
                    { label: o.backupDir, value: <code className="font-mono text-sm break-all">{plan.data.backup_dir}</code> },
                  ]}
                />
                <div className="eyebrow mt-4 mb-2">{o.changes}</div>
                <ul className="space-y-1.5">
                  {plan.data.changes.map((c, i) => (
                    <li key={i} className="flex gap-2.5 text-base text-fg-2"><span className="mt-2 size-1.5 shrink-0 rounded-full bg-accent-2" aria-hidden />{c}</li>
                  ))}
                </ul>
                <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
                  <CodeBlock label={o.before} text={plan.data.before} maxHeight={220} wrap={false} />
                  <CodeBlock label={o.after} text={plan.data.after} maxHeight={220} wrap={false} />
                </div>
              </>
            )}
          </>
        );
      case 5:
        return (
          <>
            <StepHeading title={o.consentTitle} body={o.consentBody} />
            {installed && !installResult && <Callout tone="ok" className="mb-4">{o.alreadyInstalled}</Callout>}
            {installResult?.ok && (
              <Callout tone={installResult.verified ? "ok" : "warn"} title={installResult.verified ? o.installOk : o.installUnverified} className="mb-4">
                <p>{installResult.message}</p>
                {installResult.backup_path && <p className="mt-1 text-sm">{o.backupPath}: <code className="font-mono break-all">{installResult.backup_path}</code></p>}
                {installResult.problems.length > 0 && <ul className="mt-1 list-disc pl-4.5">{installResult.problems.map((p) => <li key={p}>{p}</li>)}</ul>}
              </Callout>
            )}
            {installError && <Callout tone="danger" title={o.installFailed} className="mb-4"><span className="break-words">{installError}</span></Callout>}
            {skippedInstall && !installed && <Callout tone="warn" className="mb-4">{o.skipped}</Callout>}
            {plan.data === null && plan.error ? (
              <Callout tone="warn">{o.consentNeedPreview}</Callout>
            ) : (
              <>
                <Callout tone="info" icon={Lightbulb} className="mb-4">{o.consentFailOpen}</Callout>
                <div className="rounded-xl border border-line-strong bg-surface-2 p-4">
                  <Checkbox checked={consent} onChange={setConsent} disabled={installing}>{o.consentCheck}</Checkbox>
                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    <Button variant={installed ? "secondary" : "primary"} disabled={!consent || plan.data === null} loading={installing} onClick={() => void install()}>
                      {installed ? o.reinstall : o.install}
                    </Button>
                    {!installed && (
                      <Button variant="ghost" disabled={installing} onClick={() => { setSkippedInstall(true); setStep(6); }}>{o.skipInstall}</Button>
                    )}
                  </div>
                </div>
              </>
            )}
            {plan.data === null && plan.error && !installed && (
              <Button variant="ghost" className="mt-3" onClick={() => { setSkippedInstall(true); setStep(6); }}>{o.skipInstall}</Button>
            )}
          </>
        );
      case 6:
        return (
          <>
            <StepHeading title={o.modeTitle} body={o.modeBody} />
            <div className="rounded-xl border border-line bg-surface-2 p-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-sm text-fg-3">{o.modeCurrent}</span>
                {mode ? <ModeBadge mode={mode} size="lg" /> : <span className="text-fg-3">{t.common.unknown}</span>}
              </div>
              <p className="mt-3 text-base text-fg-2">{t.enums.mode.monitor.description}</p>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                {mode === "monitor" ? (
                  <span className="flex items-center gap-2 text-base font-medium text-ok"><CircleCheck className="size-5" aria-hidden />{o.modeActive}</span>
                ) : (
                  <Button variant="primary" icon={Eye} loading={modeBusy} onClick={() => void activateMonitor()}>{o.modeActivate}</Button>
                )}
              </div>
            </div>
            {modeError && <Callout tone="danger" title={o.modeFailed} className="mt-4"><span className="break-words">{modeError}</span></Callout>}
            <p className="mt-4 text-sm text-fg-3">{o.modeLater}</p>
          </>
        );
      case 7:
        return (
          <>
            <StepHeading title={o.testTitle} body={o.testBody} />
            <div className="flex flex-wrap items-center gap-3">
              <Button variant={test ? "secondary" : "primary"} icon={FlaskConical} loading={testing} onClick={() => void runTest()}>
                {testing ? o.testRunning : test ? o.testRunAgain : o.testRun}
              </Button>
              {test && !testing && <span className="flex items-center gap-2 text-base text-fg-2"><CircleCheck className="size-5 text-ok" aria-hidden />{o.testDone}</span>}
            </div>
            {testError && (
              <Callout tone="danger" title={o.testFailed} className="mt-4">
                <span className="break-words">{testError}</span>
              </Callout>
            )}
          </>
        );
      case 8:
        return (
          <>
            <StepHeading title={o.verifyTitle} body={o.verifyBody} />
            {!test ? <Callout tone="neutral">{o.verifyNone}</Callout> : (
              <div
                className="rounded-xl border p-4"
                style={{
                  borderColor: `color-mix(in srgb, var(${test.ok ? "--ok" : "--danger"}) 35%, var(--line))`,
                  background: `color-mix(in srgb, var(${test.ok ? "--ok" : "--danger"}) 6%, var(--surface))`,
                }}
              >
                <div className="flex items-center gap-2.5 text-lg font-semibold text-fg">
                  {test.ok ? <CircleCheck className="size-5 text-ok" aria-hidden /> : <CircleX className="size-5 text-danger" aria-hidden />}
                  {test.ok ? o.verifyOk : o.verifyNotOk}
                </div>
                <DefList
                  className="mt-3"
                  items={[
                    { label: o.eventId, value: test.event_id != null ? <code className="font-mono text-sm">#{test.event_id}</code> : <span className="text-fg-3">{t.common.notAvailable}</span> },
                    { label: o.roundTrip, value: <span className="tabular">{test.latency_ms.toFixed(1)} ms</span> },
                    { label: o.decisionGiven, value: test.decision ? <ActualBadge decision={test.decision} /> : <span className="text-fg-3">{t.common.notAvailable}</span> },
                    { label: o.message, value: <span className="break-words">{test.message}</span> },
                  ]}
                />
                {test.event_id != null && (
                  <Button size="sm" className="mt-4" icon={Eye} onClick={() => viewEvent(test.event_id as number)}>{o.viewEvent}</Button>
                )}
              </div>
            )}
          </>
        );
      default:
        return (
          <div className="flex h-full flex-col items-start justify-center">
            <LogoMark size={56} />
            <h3 className="mt-4 text-3xl font-semibold tracking-tight text-fg">{o.finishTitle}</h3>
            <p className="mt-1.5 text-base text-fg-2">{o.finishBody}</p>
            <ul className="mt-5 space-y-2">
              <StatusLine ok={installed}>{installed ? o.finishInstalled : o.finishNotInstalled}</StatusLine>
              <StatusLine ok={mode === "monitor"}>{fmt(o.finishMode, { mode: mode ? t.enums.mode[mode].label : t.common.unknown })}</StatusLine>
              <StatusLine ok={!!test?.ok}>{test?.ok ? o.finishTestOk : o.finishTestSkipped}</StatusLine>
            </ul>
            <Callout tone="neutral" className="mt-5 max-w-2xl">{o.finishReminder}</Callout>
          </div>
        );
    }
  })();

  return (
    <Dialog
      open
      onClose={close}
      width={1080}
      tone="var(--accent-2)"
      title={<span className="flex items-baseline gap-3">{o.title}<span className="tabular text-base font-normal text-fg-3">{fmt(o.stepOf, { n: step + 1, total: TOTAL })}</span></span>}
      footer={
        <div className="flex w-full items-center justify-between gap-3">
          <Button variant="ghost" onClick={skipSetup} title={o.skipSetupHint}>{o.skipSetup}</Button>
          <div className="flex items-center gap-2">
            <Button icon={ArrowLeft} disabled={step === 0} onClick={() => setStep((s) => Math.max(0, s - 1))}>{t.common.back}</Button>
            {step < TOTAL - 1 ? (
              <Button variant="primary" disabled={nextBlocked} onClick={() => setStep((s) => Math.min(TOTAL - 1, s + 1))} data-autofocus>
                {t.common.next}
                <ArrowRight className="size-4" aria-hidden />
              </Button>
            ) : (
              <Button variant="primary" icon={LayoutDashboard} onClick={finish} data-autofocus>{o.openDashboard}</Button>
            )}
          </div>
        </div>
      }
    >
      <div className="grid grid-cols-[13.5rem_minmax(0,1fr)] gap-7 pt-2">
        <ol aria-label={o.steps} className="space-y-0.5 border-r border-line pr-4">
          {STEP_KEYS.map((key, i) => {
            const done = i < step;
            const current = i === step;
            return (
              <li key={key} aria-current={current ? "step" : undefined} className={cx("flex items-center gap-2.5 rounded-lg px-2 py-1.5 text-base", current ? "bg-surface-2 font-medium text-fg" : done ? "text-fg-2" : "text-fg-3")}>
                <span
                  className={cx(
                    "tabular flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold",
                    current ? "bg-accent-2 text-bg" : done ? "bg-ok/20 text-ok" : "border border-line-strong text-fg-3",
                  )}
                >
                  {done ? <Check className="size-3.5" aria-hidden /> : i + 1}
                </span>
                <span className="truncate">{o[key]}</span>
              </li>
            );
          })}
        </ol>
        <div className="h-[30rem] min-w-0 overflow-y-auto pr-1" aria-live="polite">{body}</div>
      </div>
    </Dialog>
  );
}
