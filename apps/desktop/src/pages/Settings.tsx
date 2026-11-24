import { useEffect, useState, type ReactNode } from "react";
import {
  DatabaseBackup, FlaskConical, FolderOpen, Pause, Play, Settings as SettingsIcon, ShieldCheck, ShieldX, Trash2, Wand2,
} from "lucide-react";
import { ConfirmDialog } from "../components/overlay";
import { Page } from "../components/Page";
import { Button, Callout, Card, DefList, Field, PageHeader, Segmented, Switch, TextInput, cx } from "../components/ui";
import { fmt, useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { errorMessage, formatNumber } from "../lib/format";
import { useApp, type Lang, type ThemeSetting } from "../store/app";
import type { Config, IntegrityReport } from "../lib/types";

function Row({ title, hint, children }: { title: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-6 border-b border-line/70 py-3.5 first:pt-0 last:border-b-0 last:pb-0">
      <div className="min-w-0">
        <div className="text-base font-medium text-fg">{title}</div>
        {hint && <div className="mt-0.5 text-sm text-fg-3">{hint}</div>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

/** Integer setting saved on blur / Enter, with range validation. */
function NumberSetting({ label, hint, value, min, max, onSave }: { label: string; hint: string; value: number; min: number; max: number; onSave: (n: number) => Promise<void> }) {
  const t = useT();
  const [text, setText] = useState(String(value));
  const [busy, setBusy] = useState(false);
  useEffect(() => setText(String(value)), [value]);
  const n = Number(text);
  const valid = /^\d+$/.test(text.trim()) && n >= min && n <= max;
  const commit = () => {
    if (!valid || n === value || busy) return;
    setBusy(true);
    void onSave(n).finally(() => setBusy(false));
  };
  return (
    <Field label={label} hint={valid ? hint : <span role="alert" className="text-danger">{fmt(t.settings.invalidNumber, { min, max })}</span>}>
      <TextInput
        inputMode="numeric"
        value={text}
        disabled={busy}
        aria-invalid={!valid}
        onChange={(e) => setText(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => e.key === "Enter" && commit()}
        className={cx("tabular max-w-40", !valid && "border-danger!")}
      />
    </Field>
  );
}

function IntegrityResult({ report }: { report: IntegrityReport }) {
  const t = useT();
  const s = t.settings;
  const locale = useLocale();
  const Icon = report.ok ? ShieldCheck : ShieldX;
  return (
    <div
      role="status"
      className="mt-3 rounded-xl border p-4"
      style={{
        borderColor: `color-mix(in srgb, var(${report.ok ? "--ok" : "--danger"}) 35%, var(--line))`,
        background: `color-mix(in srgb, var(${report.ok ? "--ok" : "--danger"}) 6%, var(--surface))`,
      }}
    >
      <div className="flex items-center gap-2.5 text-lg font-semibold text-fg">
        <Icon className={cx("size-5", report.ok ? "text-ok" : "text-danger")} aria-hidden />
        {report.ok ? s.integrityOk : s.integrityBroken}
      </div>
      <DefList
        className="mt-3"
        items={[
          { label: s.integrityChecked, value: <span className="tabular">{formatNumber(report.checked, locale)}</span> },
          { label: s.integrityBridged, value: <span className="tabular" title={s.integrityBridgedHint}>{formatNumber(report.bridged_breaks, locale)}</span> },
          ...(report.first_bad_id != null ? [{ label: s.integrityFirstBad, value: <code className="font-mono text-sm">#{report.first_bad_id}</code> }] : []),
          ...(report.problem ? [{ label: s.integrityProblem, value: <span className="break-words text-danger">{report.problem}</span> }] : []),
          { label: s.integritySqlite, value: <code className="font-mono text-sm break-all">{report.sqlite_integrity}</code> },
        ]}
      />
      <p className="mt-3 text-sm text-fg-3">{s.integrityCaveat}</p>
    </div>
  );
}

export default function SettingsPage() {
  const t = useT();
  const s = t.settings;
  const locale = useLocale();
  const config = useApp((st) => st.config);
  const status = useApp((st) => st.status);
  const demo = useApp((st) => st.demo);
  const theme = useApp((st) => st.theme);
  const language = useApp((st) => st.language);
  const toast = useApp((st) => st.toast);
  const { setTheme, setLanguage, setDemo, setPaused, patchConfig, setOnboardingOpen, bumpEpoch } = useApp.getState();

  const [pauseAsk, setPauseAsk] = useState(false);
  const [pauseBusy, setPauseBusy] = useState(false);
  const [integrity, setIntegrity] = useState<IntegrityReport | null>(null);
  const [integrityBusy, setIntegrityBusy] = useState(false);
  const [backupPath, setBackupPath] = useState<string | null>(null);
  const [backupBusy, setBackupBusy] = useState(false);
  const [deleteStep, setDeleteStep] = useState<0 | 1 | 2>(0);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const paused = status?.paused ?? false;

  const save = async (patch: Partial<Config>) => {
    try {
      await patchConfig(patch);
      toast("ok", t.common.saved);
    } catch (e) {
      toast("danger", `${s.saveFailed}: ${errorMessage(e)}`);
    }
  };
  const togglePause = async (next: boolean) => {
    setPauseBusy(true);
    try {
      await setPaused(next);
      setPauseAsk(false);
    } catch (e) {
      toast("danger", errorMessage(e));
    } finally {
      setPauseBusy(false);
    }
  };
  const runIntegrity = async () => {
    setIntegrityBusy(true);
    try {
      setIntegrity(await backend.verifyIntegrity());
    } catch (e) {
      toast("danger", errorMessage(e));
    } finally {
      setIntegrityBusy(false);
    }
  };
  const runBackup = async () => {
    setBackupBusy(true);
    try {
      setBackupPath(await backend.backupDatabase());
    } catch (e) {
      toast("danger", errorMessage(e));
    } finally {
      setBackupBusy(false);
    }
  };
  const deleteAll = async () => {
    setDeleteBusy(true);
    try {
      const n = await backend.deleteAllData();
      setDeleteStep(0);
      setIntegrity(null);
      toast("ok", fmt(s.deleted, { n: formatNumber(n, locale) }));
      bumpEpoch();
    } catch (e) {
      toast("danger", errorMessage(e));
    } finally {
      setDeleteBusy(false);
    }
  };
  const open = (path: string) => backend.openPath(path).catch((e: unknown) => toast("danger", `${s.openFailed}: ${errorMessage(e)}`));
  const parentDir = (p: string) => p.replace(/[\\/][^\\/]*$/, "") || p;

  const paths: { label: string; path: string | undefined; target?: string }[] = [
    { label: s.dataDir, path: status?.data_dir },
    { label: s.configDir, path: status?.config_dir },
    { label: s.dbPath, path: status?.db_path, target: status ? parentDir(status.db_path) : undefined },
  ];

  return (
    <Page>
      <PageHeader title={s.title} description={s.description} icon={SettingsIcon} />
      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-2">
        <div className="flex min-w-0 flex-col gap-5">
          <Card title={s.appearance} subtitle={s.appearanceHint}>
            <Row title={t.common.language} hint={s.languageHint}>
              <Segmented<Lang>
                label={t.common.language}
                value={language}
                onChange={setLanguage}
                options={[{ value: "en", label: t.common.langEn }, { value: "nl", label: t.common.langNl }]}
              />
            </Row>
            <Row title={t.common.theme} hint={s.themeHint}>
              <Segmented<ThemeSetting>
                label={t.common.theme}
                value={theme}
                onChange={setTheme}
                options={[
                  { value: "dark", label: t.common.themeDark },
                  { value: "light", label: t.common.themeLight },
                  { value: "system", label: t.common.themeSystem },
                ]}
              />
            </Row>
          </Card>

          <Card title={s.monitoring} subtitle={s.monitoringHint}>
            <Callout tone={paused ? "warn" : "ok"} icon={paused ? Pause : undefined} title={paused ? s.monitoringPaused : s.monitoringActive} className="mb-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <span>{paused ? s.monitoringPausedBody : s.monitoringActiveBody}</span>
                {paused ? (
                  <Button size="sm" variant="primary" icon={Play} loading={pauseBusy} onClick={() => void togglePause(false)}>{s.resume}</Button>
                ) : (
                  <Button size="sm" icon={Pause} disabled={!status} onClick={() => setPauseAsk(true)}>{s.pause}</Button>
                )}
              </div>
            </Callout>
            {config ? (
              <>
                <Row title={s.notifications} hint={s.notificationsHint}>
                  <Switch label={s.notifications} checked={config.notifications} onChange={(v) => void save({ notifications: v })} />
                </Row>
                <div className="grid grid-cols-1 gap-5 pt-4 sm:grid-cols-2">
                  <NumberSetting label={s.retention} hint={s.retentionHint} value={config.retention_days} min={1} max={3650} onSave={(n) => save({ retention_days: n })} />
                  <NumberSetting label={s.correlation} hint={s.correlationHint} value={config.correlation_window_minutes} min={1} max={1440} onSave={(n) => save({ correlation_window_minutes: n })} />
                </div>
              </>
            ) : (
              <p className="text-base text-fg-3">{s.configUnavailable}</p>
            )}
          </Card>

          <Card title={s.paths} subtitle={s.pathsHint}>
            <ul>
              {paths.map((p) => (
                <li key={p.label} className="flex items-center justify-between gap-4 border-b border-line/70 py-3 first:pt-0 last:border-b-0 last:pb-0">
                  <div className="min-w-0">
                    <div className="text-sm text-fg-3">{p.label}</div>
                    <code className="block truncate font-mono text-sm text-fg" title={p.path}>{p.path ?? t.common.notAvailable}</code>
                  </div>
                  <Button size="sm" variant="ghost" icon={FolderOpen} disabled={!p.path} aria-label={`${t.common.openFolder}: ${p.label}`} onClick={() => p.path && void open(p.target ?? p.path)}>
                    {t.common.open}
                  </Button>
                </li>
              ))}
            </ul>
          </Card>
        </div>

        <div className="flex min-w-0 flex-col gap-5">
          <Card title={s.data} subtitle={s.dataHint}>
            <Row title={s.integrity} hint={s.integrityBody}>
              <Button icon={ShieldCheck} loading={integrityBusy} onClick={() => void runIntegrity()}>{s.integrityRun}</Button>
            </Row>
            {integrity && <IntegrityResult report={integrity} />}
            <div className={cx(integrity && "mt-4 border-t border-line/70 pt-3.5")}>
              <Row title={s.backup} hint={s.backupBody}>
                <Button icon={DatabaseBackup} loading={backupBusy} onClick={() => void runBackup()}>{s.backupRun}</Button>
              </Row>
            </div>
            {backupPath && (
              <div role="status" className="mt-3 flex items-center justify-between gap-3 rounded-lg border border-line bg-surface-2 px-3 py-2.5">
                <div className="min-w-0">
                  <div className="text-sm text-fg-3">{s.backupDone}</div>
                  <code className="block truncate font-mono text-sm text-fg" title={backupPath}>{backupPath}</code>
                </div>
                <Button size="sm" variant="ghost" icon={FolderOpen} onClick={() => void open(parentDir(backupPath))}>{t.common.openFolder}</Button>
              </div>
            )}
            <div className="mt-5 rounded-xl border border-danger/40 p-4">
              <div className="eyebrow text-danger!">{s.dangerZone}</div>
              <div className="mt-2 flex items-center justify-between gap-6">
                <div className="min-w-0">
                  <div className="text-base font-medium text-fg">{s.deleteAll}</div>
                  <div className="mt-0.5 text-sm text-fg-3">{s.deleteAllBody}</div>
                </div>
                <Button variant="outline-danger" icon={Trash2} onClick={() => setDeleteStep(1)}>{s.deleteAll}</Button>
              </div>
            </div>
          </Card>

          <Card title={s.demo} accent={demo ? "var(--warn)" : undefined}>
            <div className="flex items-start gap-3">
              <FlaskConical className="mt-0.5 size-5 shrink-0 text-warn" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-base text-fg-2">{s.demoBody}</p>
                <ul className="mt-2.5 list-disc space-y-1 pl-4.5 text-base text-fg-2">
                  {[s.demoPoint1, s.demoPoint2, s.demoPoint3].map((line) => <li key={line}>{line}</li>)}
                </ul>
              </div>
            </div>
            <div className="mt-4 flex items-center justify-between gap-4 rounded-lg border border-line bg-surface-2 px-4 py-3">
              <div>
                <div className="text-base font-medium text-fg">{s.demoToggle}</div>
                <div className="text-sm text-fg-3">{demo ? s.demoOn : s.demoOff}</div>
              </div>
              <Switch label={s.demoToggle} checked={demo} onChange={setDemo} />
            </div>
          </Card>

          <Card title={s.onboarding}>
            <div className="flex items-center justify-between gap-6">
              <p className="min-w-0 text-base text-fg-2">{s.onboardingBody}</p>
              <Button icon={Wand2} onClick={() => setOnboardingOpen(true)}>{s.onboardingRun}</Button>
            </div>
          </Card>
        </div>
      </div>

      <ConfirmDialog open={pauseAsk} title={s.pauseConfirmTitle} confirmLabel={s.pause} busy={pauseBusy} onConfirm={() => void togglePause(true)} onCancel={() => setPauseAsk(false)}>
        <p>{s.pauseConfirmBody}</p>
      </ConfirmDialog>
      <ConfirmDialog open={deleteStep === 1} danger title={s.deleteConfirm1Title} confirmLabel={s.deleteConfirm1Cta} onConfirm={() => setDeleteStep(2)} onCancel={() => setDeleteStep(0)}>
        <p>{s.deleteConfirm1Body}</p>
      </ConfirmDialog>
      <ConfirmDialog
        open={deleteStep === 2}
        danger
        title={s.deleteConfirm2Title}
        confirmLabel={s.deleteConfirm2Cta}
        requireText={s.deleteWord}
        requireTextLabel={fmt(s.deleteTypeLabel, { word: s.deleteWord })}
        busy={deleteBusy}
        onConfirm={() => void deleteAll()}
        onCancel={() => setDeleteStep(0)}
      >
        <p>{s.deleteConfirm2Body}</p>
      </ConfirmDialog>
    </Page>
  );
}
