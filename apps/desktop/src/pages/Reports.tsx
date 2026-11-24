import { useMemo, useState, type ReactNode } from "react";
import {
  Braces, CalendarDays, CalendarRange, CheckCircle2, Download, EyeOff, FileBarChart, FileCode2, FileSpreadsheet, FileText,
  FolderGit2, FolderOpen, Ghost, Info, ScanSearch, ShieldAlert, Users, type LucideIcon,
} from "lucide-react";
import { Page } from "../components/Page";
import { Button, Callout, Card, Field, Mono, PageHeader, Segmented, Select, TextInput, cx, type Option } from "../components/ui";
import { fmt, useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { errorMessage, formatNumber, formatTime } from "../lib/format";
import { useAsync, useDebounced } from "../lib/hooks";
import { useApp } from "../store/app";
import { ALL_CATEGORIES } from "../theme/palette";
import type { EventQuery, ExportFormat, ExportResult, ReportKind, ReportResult, RiskCategory } from "../lib/types";

const KINDS: { id: ReportKind; icon: LucideIcon }[] = [
  { id: "daily", icon: CalendarDays },
  { id: "weekly", icon: CalendarRange },
  { id: "project", icon: FolderGit2 },
  { id: "agent_comparison", icon: Users },
  { id: "shadow", icon: Ghost },
  { id: "incident", icon: ShieldAlert },
  { id: "coverage", icon: ScanSearch },
];

const FORMATS: { id: ExportFormat; icon: LucideIcon }[] = [
  { id: "json", icon: Braces },
  { id: "csv", icon: FileSpreadsheet },
  { id: "sarif", icon: FileCode2 },
  { id: "html", icon: FileText },
];

type WindowId = "24" | "168" | "720";
const PREVIEW_LIMIT = 5000;

/** Raw field names of the audit record that every export contains. */
const EXPORT_FIELDS = [
  "id", "uuid", "ts_utc", "agent", "agent_version", "session_id", "workspace", "hook_event", "phase", "action_type", "tool",
  "summary", "action", "input_redacted", "risk.score", "risk.level", "risk.findings", "policy_name", "policy_version",
  "matched_rules", "mode", "simulated_decision", "actual_decision", "outcome", "coverage", "latency_us", "prev_hash", "hash",
];

function ChoiceCard({ selected, onSelect, icon: Icon, title, body }: { selected: boolean; onSelect: () => void; icon: LucideIcon; title: string; body: string }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      onClick={onSelect}
      className={cx(
        "flex min-w-0 items-start gap-3 rounded-lg border p-3 text-left transition-colors",
        selected ? "border-accent bg-accent/8 shadow-[inset_0_0_0_1px_var(--accent)]" : "border-line bg-surface-2 hover:border-line-strong",
      )}
    >
      <Icon className={cx("mt-0.5 size-4.5 shrink-0", selected ? "text-accent" : "text-fg-3")} aria-hidden />
      <span className="min-w-0">
        <span className="block text-base font-semibold text-fg">{title}</span>
        <span className="mt-0.5 block text-sm text-fg-3">{body}</span>
      </span>
    </button>
  );
}

function ResultRow({ icon: Icon, title, meta, path, onOpen }: { icon: LucideIcon; title: ReactNode; meta?: ReactNode; path: string; onOpen: () => void }) {
  const t = useT();
  return (
    <li className="flex items-center gap-3 rounded-lg border border-line bg-surface-2 px-3 py-2.5">
      <Icon className="size-4.5 shrink-0 text-ok" aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="truncate text-base font-medium text-fg">{title}</span>
          {meta && <span className="tabular shrink-0 text-sm text-fg-3">{meta}</span>}
        </div>
        <Mono text={path} className="text-fg-2" />
      </div>
      <Button size="sm" icon={FolderOpen} onClick={onOpen}>{t.common.open}</Button>
    </li>
  );
}

function useWindowOptions(): Option<WindowId>[] {
  const t = useT();
  return [
    { value: "24", label: t.common.window24h },
    { value: "168", label: t.common.window7d },
    { value: "720", label: t.common.window30d },
  ];
}

function useOpenPath(): (path: string) => void {
  const t = useT();
  const toast = useApp((s) => s.toast);
  return (path) => {
    backend.openPath(path).catch((e: unknown) => toast("danger", `${t.reports.openFailed}: ${errorMessage(e)}`));
  };
}

function DemoNote() {
  const t = useT();
  const demo = useApp((s) => s.demo);
  if (!demo) return null;
  return <p className="flex items-center gap-2 text-sm text-warn"><Info className="size-4 shrink-0" aria-hidden />{t.common.demoActionBlocked}</p>;
}

function GenerateCard() {
  const t = useT();
  const r = t.reports;
  const locale = useLocale();
  const toast = useApp((s) => s.toast);
  const openPath = useOpenPath();
  const windows = useWindowOptions();
  const [kind, setKind] = useState<ReportKind>("daily");
  const [win, setWin] = useState<WindowId>("24");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<(ReportResult & { at: string; key: number })[]>([]);

  const generate = async () => {
    setBusy(true);
    try {
      const res = await backend.generateReport(kind, Number(win));
      setHistory((h) => [{ ...res, at: new Date().toISOString(), key: Date.now() }, ...h].slice(0, 20));
      toast("ok", r.generated);
    } catch (e) {
      toast("danger", `${r.generateFailed}: ${errorMessage(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title={r.generateTitle} subtitle={r.generateHint} className="h-full">
      <div className="space-y-5">
        <div>
          <div className="mb-2 text-sm font-medium text-fg-2">{r.kindLabel}</div>
          <div role="radiogroup" aria-label={r.kindLabel} className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            {KINDS.map((k) => (
              <ChoiceCard key={k.id} selected={kind === k.id} onSelect={() => setKind(k.id)} icon={k.icon} title={r.kind[k.id].title} body={r.kind[k.id].body} />
            ))}
          </div>
        </div>
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="mb-1.5 text-sm font-medium text-fg-2">{t.common.window}</div>
            <Segmented label={t.common.window} value={win} onChange={setWin} options={windows} />
          </div>
          <Button variant="primary" icon={FileBarChart} loading={busy} onClick={() => void generate()}>{busy ? r.generating : r.generate}</Button>
        </div>
        <DemoNote />
        <div className="border-t border-line pt-4">
          <div className="eyebrow mb-2">{r.historyTitle}</div>
          {history.length === 0 ? <p className="text-base text-fg-3">{r.historyEmpty}</p> : (
            <>
              <ul className="space-y-2" aria-live="polite">
                {history.map((h) => (
                  <ResultRow key={h.key} icon={CheckCircle2} title={h.title} meta={formatTime(h.at, locale)} path={h.path} onOpen={() => openPath(h.path)} />
                ))}
              </ul>
              <p className="mt-2 text-sm text-fg-3">{r.historyNote}</p>
            </>
          )}
        </div>
      </div>
    </Card>
  );
}

function ExportCard() {
  const t = useT();
  const r = t.reports;
  const locale = useLocale();
  const toast = useApp((s) => s.toast);
  const openPath = useOpenPath();
  const windows = useWindowOptions();
  const [format, setFormat] = useState<ExportFormat>("json");
  const [win, setWin] = useState<WindowId>("168");
  const [minScoreText, setMinScoreText] = useState("0");
  const [category, setCategory] = useState<RiskCategory | "">("");
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<(ExportResult & { format: ExportFormat; key: number })[]>([]);

  const minScore = Math.max(0, Math.min(100, Math.round(Number(minScoreText) || 0)));
  const filters = useDebounced(useMemo(() => ({ win, minScore, category }), [win, minScore, category]), 300);

  // `since` is computed when the filters change (not on every render) so the preview is stable.
  const query = useMemo<EventQuery>(() => {
    const q: EventQuery = { since: new Date(Date.now() - Number(filters.win) * 3600_000).toISOString() };
    if (filters.minScore > 0) q.min_score = filters.minScore;
    if (filters.category) q.category = filters.category;
    return q;
  }, [filters]);

  // Exact count from the backend; exports themselves are capped at PREVIEW_LIMIT rows.
  const preview = useAsync(() => backend.countEvents(query), [query]);
  const count = preview.refreshing ? null : preview.data;
  const countLabel = count == null ? null : count > PREVIEW_LIMIT ? fmt(r.includedMany, { count: formatNumber(count, locale), cap: formatNumber(PREVIEW_LIMIT, locale) }) : formatNumber(count, locale);

  const categoryOptions = useMemo<Option<RiskCategory | "">[]>(() => [
    { value: "", label: r.categoryAny },
    ...ALL_CATEGORIES.map((c) => ({ value: c, label: t.enums.category[c] })).sort((a, b) => a.label.localeCompare(b.label, locale)),
  ], [r, t, locale]);

  const run = async () => {
    setBusy(true);
    try {
      const res = await backend.exportEvents(format, query);
      setResults((list) => [{ ...res, format, key: Date.now() }, ...list].slice(0, 10));
      toast("ok", fmt(r.exported, { n: formatNumber(res.count, locale) }));
    } catch (e) {
      toast("danger", `${r.exportFailed}: ${errorMessage(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title={r.exportTitle} subtitle={r.exportHint} className="h-full">
      <div className="space-y-5">
        <div>
          <div className="mb-2 text-sm font-medium text-fg-2">{r.formatLabel}</div>
          <div role="radiogroup" aria-label={r.formatLabel} className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            {FORMATS.map((f) => (
              <ChoiceCard key={f.id} selected={format === f.id} onSelect={() => setFormat(f.id)} icon={f.icon} title={r.format[f.id].title} body={r.format[f.id].body} />
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 items-start gap-4 sm:grid-cols-[auto_9rem_minmax(0,1fr)]">
          <div>
            <div className="mb-1.5 text-sm font-medium text-fg-2">{t.common.window}</div>
            <Segmented label={t.common.window} value={win} onChange={setWin} options={windows} />
          </div>
          <Field label={r.minScore} hint={r.minScoreHint}>
            <TextInput type="number" min={0} max={100} step={5} inputMode="numeric" value={minScoreText} onChange={(e) => setMinScoreText(e.target.value)} />
          </Field>
          <Field label={t.common.category}>
            <Select value={category} onChange={setCategory} options={categoryOptions} aria-label={t.common.category} className="w-full" />
          </Field>
        </div>

        <section aria-label={r.includedTitle} className="rounded-xl border border-line bg-surface-2 p-4">
          <h4 className="eyebrow">{r.includedTitle}</h4>
          <div className="mt-2 flex min-h-9 items-baseline gap-3" aria-live="polite">
            {preview.error ? <span className="text-base text-danger">{r.includedCountFailed}</span>
              : countLabel == null ? <span className="text-base text-fg-3">{r.includedCounting}</span>
              : (
                <>
                  <span className="tabular text-3xl leading-9 font-semibold tracking-tight text-fg">{countLabel}</span>
                  <span className="text-base text-fg-2">{r.includedCount}</span>
                </>
              )}
          </div>
          <div className="mt-3 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div>
              <div className="mb-1.5 text-sm font-medium text-fg-2">{r.includedFields}</div>
              <div className="flex flex-wrap gap-1">
                {EXPORT_FIELDS.map((f) => <code key={f} className="rounded border border-line bg-surface px-1.5 py-0.5 text-xs text-fg-2">{f}</code>)}
              </div>
            </div>
            <div>
              <div className="mb-1.5 flex items-center gap-1.5 text-sm font-medium text-fg-2"><EyeOff className="size-4" aria-hidden />{r.includedRedaction}</div>
              <ul className="list-disc space-y-1 pl-4.5 text-sm text-fg-2">
                <li>{r.redaction1}</li>
                <li>{r.redaction2}</li>
                <li>{r.redaction3}</li>
                <li>{r.redaction4}</li>
              </ul>
            </div>
          </div>
        </section>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            {count === 0 ? <span className="text-sm text-fg-3">{r.nothingToExport}</span> : <DemoNote />}
          </div>
          <Button variant="primary" icon={Download} loading={busy} disabled={count === 0} onClick={() => void run()}>
            {busy ? r.exporting : fmt(r.export, { format: r.format[format].title })}
          </Button>
        </div>

        {results.length > 0 && (
          <ul className="space-y-2 border-t border-line pt-4" aria-live="polite">
            {results.map((res) => (
              <ResultRow
                key={res.key}
                icon={CheckCircle2}
                title={fmt(r.exported, { n: formatNumber(res.count, locale) })}
                meta={r.format[res.format].title}
                path={res.path}
                onOpen={() => openPath(res.path)}
              />
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}

export default function ReportsPage() {
  const t = useT();
  return (
    <Page>
      <PageHeader title={t.reports.title} description={t.reports.description} icon={FileBarChart} />
      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-2">
        <GenerateCard />
        <ExportCard />
      </div>
      <Callout tone="neutral" className="mt-5">{t.common.redactedNote}</Callout>
    </Page>
  );
}
