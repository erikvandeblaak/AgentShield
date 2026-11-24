import { useEffect, useMemo, useState } from "react";
import {
  Activity, ArrowRight, Ban, Clock, FlaskConical, Gauge, History, ListTree, MousePointerClick, Search, ShieldX, Trash2, TriangleAlert,
} from "lucide-react";
import { DecisionBadge, RiskPill } from "../components/badges";
import { Chart, type ChartClick } from "../components/Chart";
import { EventTable, type EventColumnId } from "../components/EventTable";
import { ConfirmDialog, Dialog } from "../components/overlay";
import { Page } from "../components/Page";
import {
  AsyncView, Badge, Button, Callout, Card, EmptyState, ErrorState, Field, Kpi, PageHeader, Segmented, Select, Skeleton, Spinner, cx,
} from "../components/ui";
import { fmt, useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { tooltipHtml } from "../lib/escape";
import {
  basename, errorMessage, formatDateTime, formatDuration, formatNumber, formatSmartTime, formatTime, shortId,
} from "../lib/format";
import { useAsync } from "../lib/hooks";
import { navigate, useRoute } from "../lib/router";
import { useApp } from "../store/app";
import { useChartTheme } from "../theme/echarts";
import { DECISION_VAR, FAMILIES, familyOf, v, type Family } from "../theme/palette";
import type { EventRow, Phase, PolicyDecision, ReplayResult, SessionSummary } from "../lib/types";

const EVENT_LIMIT = 2000;
const DECISIONS: PolicyDecision[] = ["allow", "warn", "ask", "require_sandbox", "deny"];
const SESSION_COLUMNS: EventColumnId[] = ["time", "phase", "action", "tool", "risk", "simulated", "actual", "outcome", "policy"];
const SYMBOL: Record<Phase, string> = { pre: "circle", post: "diamond", lifecycle: "triangle" };

const cleanId = (id: string) => shortId(id.replace(/^demo-/, ""), 8);

// ------------------------------------------------------------------ session list

function SessionItem({ s, selected, onSelect }: { s: SessionSummary; selected: boolean; onSelect: () => void }) {
  const t = useT();
  const ts = t.sessions;
  const locale = useLocale();
  return (
    <button
      type="button"
      role="option"
      aria-selected={selected}
      onClick={onSelect}
      className={cx(
        "block w-full border-b border-line/70 px-4 py-3 text-left transition-colors focus-visible:outline-offset-[-2px]",
        selected ? "bg-surface-3 shadow-[inset_2px_0_0_var(--accent-2)]" : "hover:bg-surface-2",
      )}
    >
      <span className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-base font-semibold text-fg" title={s.workspace ?? undefined}>
          {s.workspace ? basename(s.workspace) : ts.noProject}
        </span>
        <RiskPill score={s.max_score} />
      </span>
      <span className="mt-1 flex items-center gap-2 text-sm text-fg-3">
        <code className="text-sm text-fg-2" title={s.session_id}>{cleanId(s.session_id)}</code>
        <span className="tabular truncate">{formatSmartTime(s.first_ts, locale)} – {formatTime(s.last_ts, locale)}</span>
      </span>
      <span className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-fg-2">
        <span className="tabular">{fmt(ts.eventsShort, { n: formatNumber(s.events, locale) })}</span>
        {s.would_block > 0 && <span className="tabular text-warn">{fmt(ts.wouldBlockShort, { n: s.would_block })}</span>}
        {s.blocked > 0 && <span className="tabular font-medium text-danger">{fmt(ts.blockedShort, { n: s.blocked })}</span>}
        <span className="ml-auto">
          {s.ended ? <span className="text-fg-3">{ts.ended}</span> : <Badge tone="var(--ok)" dot>{ts.active}</Badge>}
        </span>
      </span>
    </button>
  );
}

// ------------------------------------------------------------------ timeline

function ShapeLegend() {
  const ts = useT().sessions;
  const items: [string, string][] = [
    ["M6 1.5a4.5 4.5 0 1 0 0 9a4.5 4.5 0 0 0 0-9Z", ts.shapePre],
    ["M6 0.8 11.2 6 6 11.2 0.8 6Z", ts.shapePost],
    ["M6 1.2 11.2 10.6H0.8Z", ts.shapeLifecycle],
  ];
  return (
    <ul aria-label={ts.shapesLabel} className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm text-fg-2">
      {items.map(([d, label]) => (
        <li key={label} className="flex items-center gap-1.5">
          <svg viewBox="0 0 12 12" width="12" height="12" aria-hidden><path d={d} fill="var(--fg-3)" /></svg>
          {label}
        </li>
      ))}
    </ul>
  );
}

function Timeline({ rows }: { rows: EventRow[] }) {
  const t = useT();
  const ts = t.sessions;
  const locale = useLocale();
  const th = useChartTheme();
  const openEvent = useApp((s) => s.openEvent);
  const byId = useMemo(() => new Map(rows.map((r) => [r.record.id, r])), [rows]);

  const option = useMemo(() => {
    const groups = new Map<Family, EventRow[]>();
    for (const row of rows) {
      const fam = familyOf(row.record.risk.categories);
      const list = groups.get(fam);
      if (list) list.push(row);
      else groups.set(fam, [row]);
    }
    // Fixed family order: colour follows the family, never its rank in this session.
    const present = FAMILIES.filter((f) => groups.has(f));
    const series: Record<string, unknown>[] = present.map((fam) => ({
      name: t.enums.family[fam],
      type: "scatter",
      z: fam === "none" ? 2 : 3,
      itemStyle: { color: th.family[fam], opacity: fam === "none" ? 0.7 : 0.95, borderColor: th.surface, borderWidth: 1 },
      emphasis: { scale: 1.5, itemStyle: { borderColor: th.fg, borderWidth: 1.5 } },
      data: (groups.get(fam) ?? []).map((row) => ({
        value: [Date.parse(row.record.ts_utc), row.record.risk.score],
        symbol: SYMBOL[row.record.phase],
        symbolSize: row.record.risk.score >= 40 ? 12 : 9,
        id: row.record.id,
      })),
    }));
    series.push({
      name: "thresholds",
      type: "scatter",
      data: [],
      silent: true,
      legendHoverLink: false,
      markLine: {
        silent: true,
        symbol: "none",
        animation: false,
        label: { position: "insideEndTop", color: th.fg3, fontFamily: th.fontSans, fontSize: 12, formatter: (p: { name?: string }) => p.name ?? "" },
        data: [
          { yAxis: 40, name: t.enums.level.medium, lineStyle: { color: th.level.medium } },
          { yAxis: 60, name: t.enums.level.high, lineStyle: { color: th.level.high } },
          { yAxis: 80, name: t.enums.level.critical, lineStyle: { color: th.level.critical } },
        ],
        lineStyle: { type: "dashed", width: 1, opacity: 0.45 },
      },
    });
    return {
      grid: { ...th.grid4, top: 40, right: 24 },
      legend: { ...th.legend, top: 0, left: 0, data: present.map((f) => t.enums.family[f]) },
      tooltip: {
        ...th.tooltip,
        trigger: "item",
        formatter: (p: { data?: { id?: number }; color?: string }) => {
          const row = p.data?.id != null ? byId.get(p.data.id) : undefined;
          if (!row) return "";
          const r = row.record;
          const title = r.summary.length > 110 ? `${r.summary.slice(0, 109)}…` : r.summary;
          const cat = r.risk.categories[0];
          return tooltipHtml(title, [
            { label: t.common.risk, value: r.risk.score, color: typeof p.color === "string" ? p.color : undefined },
            { label: t.common.time, value: formatTime(r.ts_utc, locale) },
            { label: t.common.phase, value: t.enums.phaseLong[r.phase] },
            { label: t.common.action, value: r.action_type },
            ...(cat ? [{ label: t.common.category, value: t.enums.category[cat] ?? cat }] : []),
          ], `#${r.id}`);
        },
      },
      xAxis: { type: "time", ...th.timeAxis },
      yAxis: { type: "value", min: 0, max: 100, interval: 20, ...th.valueAxis },
      series,
    };
  }, [rows, th, t, locale, byId]);

  const onClick = (p: ChartClick) => {
    const id = (p.data as { id?: number } | undefined)?.id;
    const row = id != null ? byId.get(id) : undefined;
    if (row) openEvent(row);
  };

  return (
    <>
      <Chart option={option} height={300} ariaLabel={fmt(ts.timelineAria, { n: rows.length })} onClick={onClick} className="cursor-pointer" />
      <div className="mt-2 flex flex-wrap items-center justify-between gap-x-6 gap-y-1 border-t border-line pt-3">
        <ShapeLegend />
        <span className="flex items-center gap-1.5 text-sm text-fg-3"><Gauge className="size-4" aria-hidden />{ts.axisRisk} 0–100</span>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ replay

function ReplayDialog({ sessionId, open, onClose }: { sessionId: string; open: boolean; onClose: () => void }) {
  const t = useT();
  const ts = t.sessions;
  const locale = useLocale();
  const openEventById = useApp((s) => s.openEventById);
  const presets = useAsync(() => backend.presets(), [], { enabled: open });
  const activePreset = useApp((s) => s.status?.preset);
  const [preset, setPreset] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ReplayResult | null>(null);

  useEffect(() => {
    if (!open) {
      setResult(null);
      setError(null);
    }
  }, [open]);
  useEffect(() => {
    if (preset || !presets.data?.length) return;
    // Default to a preset other than the active one: replaying the same policy shows nothing new.
    const other = presets.data.find((p) => p.id !== activePreset) ?? presets.data[0];
    if (other) setPreset(other.id);
  }, [presets.data, preset, activePreset]);

  const run = async () => {
    if (!preset) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await backend.replay(preset, sessionId, EVENT_LIMIT));
    } catch (e) {
      setError(errorMessage(e));
      setResult(null);
    } finally {
      setBusy(false);
    }
  };

  const current = presets.data?.find((p) => p.id === preset);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={ts.replayTitle}
      width={760}
      footer={<Button variant="ghost" onClick={onClose}>{t.common.close}</Button>}
    >
      <div className="space-y-4 pb-1">
        <Callout tone="info" icon={FlaskConical}>{ts.replayIntro}</Callout>
        {presets.error ? <ErrorState error={presets.error} onRetry={presets.reload} compact /> : !presets.data ? <Spinner /> : (
          <div className="flex flex-wrap items-end gap-3">
            <Field label={ts.replayPreset} className="min-w-64 flex-1">
              <Select
                value={preset}
                onChange={(p) => {
                  setPreset(p);
                  setResult(null);
                }}
                options={presets.data.map((p) => ({ value: p.id, label: p.id === activePreset ? `${p.title} (${t.shell.modeDialog.current})` : p.title }))}
                data-autofocus
              />
            </Field>
            <Button variant="primary" icon={History} loading={busy} disabled={!preset} onClick={() => void run()}>
              {busy ? ts.replayRunning : ts.replayRun}
            </Button>
          </div>
        )}
        {current && <p className="text-sm text-fg-3">{current.description}</p>}
        {error && <Callout tone="danger" title={ts.replayFailed}><span className="font-mono text-sm break-all">{error}</span></Callout>}

        {result && (
          <div className="animate-fade-in space-y-4">
            <div className="text-base font-medium text-fg">{fmt(ts.replayEvaluated, { n: formatNumber(result.evaluated, locale), preset: result.preset })}</div>
            <div className="overflow-x-auto rounded-lg border border-line">
              <table aria-label={ts.replayTableLabel} className="w-full border-collapse text-base">
                <thead>
                  <tr className="border-b border-line bg-surface-2">
                    <th scope="col" className="eyebrow px-4 py-2 text-left font-normal">{t.common.decision}</th>
                    <th scope="col" className="eyebrow px-4 py-2 text-right font-normal">{ts.replayBefore}</th>
                    <th scope="col" className="w-10" aria-hidden />
                    <th scope="col" className="eyebrow px-4 py-2 text-right font-normal">{ts.replayAfter}</th>
                    <th scope="col" className="eyebrow px-4 py-2 text-right font-normal">{ts.replayDelta}</th>
                  </tr>
                </thead>
                <tbody>
                  {DECISIONS.map((d) => {
                    const before = result.original_by_decision[d] ?? 0;
                    const after = result.by_decision[d] ?? 0;
                    const delta = after - before;
                    return (
                      <tr key={d} className="border-b border-line/70 last:border-b-0">
                        <th scope="row" className="px-4 py-2 text-left font-normal">
                          <span className="flex items-center gap-2 text-fg">
                            <span className="size-2.5 rounded-sm" style={{ background: v(DECISION_VAR[d]) }} aria-hidden />
                            {t.enums.decision[d]}
                          </span>
                        </th>
                        <td className="tabular px-4 py-2 text-right text-fg-2">{formatNumber(before, locale)}</td>
                        <td className="text-center text-fg-3"><ArrowRight className="mx-auto size-4" aria-hidden /></td>
                        <td className="tabular px-4 py-2 text-right font-semibold text-fg">{formatNumber(after, locale)}</td>
                        <td className={cx("tabular px-4 py-2 text-right", delta === 0 ? "text-fg-3" : "font-medium text-fg")}>
                          {delta === 0 ? "±0" : `${delta > 0 ? "+" : "−"}${formatNumber(Math.abs(delta), locale)}`}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div>
              <div className="mb-1.5 flex items-baseline justify-between gap-3">
                <div className="eyebrow">{ts.replayChanged}</div>
                {result.changed.length > 0 && <span className="tabular text-sm text-fg-3">{fmt(ts.replayChangedCount, { n: result.changed.length })}</span>}
              </div>
              {result.changed.length === 0 ? <p className="text-base text-fg-3">{ts.replayNoChanges}</p> : (
                <ul className="max-h-64 overflow-y-auto rounded-lg border border-line">
                  {result.changed.map((c) => (
                    <li key={c.event_id} className="border-b border-line/70 last:border-b-0">
                      <button
                        type="button"
                        onClick={() => void openEventById(c.event_id)}
                        aria-label={`${t.common.viewEvent} #${c.event_id}`}
                        className="flex w-full items-center gap-3 px-3 py-2 text-left transition-colors hover:bg-surface-2 focus-visible:outline-offset-[-2px]"
                      >
                        <code className="tabular w-14 shrink-0 text-sm text-fg-3">#{c.event_id}</code>
                        <span className="min-w-0 flex-1 truncate font-mono text-sm text-fg" title={c.summary}>{c.summary}</span>
                        <span className="flex shrink-0 items-center gap-1.5">
                          <DecisionBadge decision={c.before} />
                          <ArrowRight className="size-4 text-fg-3" aria-hidden />
                          <DecisionBadge decision={c.after} />
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </div>
    </Dialog>
  );
}

// ------------------------------------------------------------------ session detail

function SessionDetail({ summary }: { summary: SessionSummary }) {
  const t = useT();
  const ts = t.sessions;
  const locale = useLocale();
  const toast = useApp((s) => s.toast);
  const id = summary.session_id;
  const events = useAsync(() => backend.listEvents({ session_id: id, limit: EVENT_LIMIT }), [id], { refreshMs: summary.ended ? undefined : 10_000 });
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [replayOpen, setReplayOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // listEvents returns newest first.
  const asc = useMemo(() => (events.data ? [...events.data].reverse() : []), [events.data]);
  const ordered = order === "asc" ? asc : (events.data ?? []);
  const risky = useMemo(() => asc.filter((r) => r.record.phase === "pre" && r.record.risk.score >= 40).length, [asc]);
  const durationS = (Date.parse(summary.last_ts) - Date.parse(summary.first_ts)) / 1000;

  const remove = async () => {
    setDeleting(true);
    try {
      const n = await backend.deleteSession(id);
      toast("ok", fmt(ts.deleted, { n: formatNumber(n, locale) }));
      setDeleteOpen(false);
      navigate("sessions");
      useApp.getState().bumpEpoch();
    } catch (e) {
      toast("danger", `${ts.deleteFailed}: ${errorMessage(e)}`);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h2 className="truncate text-2xl font-semibold text-fg">{summary.workspace ? basename(summary.workspace) : ts.noProject}</h2>
            {summary.ended ? <Badge>{ts.ended}</Badge> : <Badge tone="var(--ok)" dot>{ts.active}</Badge>}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-sm text-fg-3">
            <code className="text-sm break-all text-fg-2">{id}</code>
            <span>{summary.agent}</span>
            {summary.workspace && <code className="truncate text-sm" title={summary.workspace}>{summary.workspace}</code>}
          </div>
          <div className="tabular mt-0.5 text-sm text-fg-3">{formatDateTime(summary.first_ts, locale)} – {formatDateTime(summary.last_ts, locale)}</div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button icon={History} onClick={() => setReplayOpen(true)}>{ts.replay}</Button>
          <Button variant="outline-danger" icon={Trash2} onClick={() => setDeleteOpen(true)}>{ts.delete}</Button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3 min-[1900px]:grid-cols-6">
        <Kpi label={ts.kpiEvents} value={formatNumber(summary.events, locale)} icon={Activity} />
        <Kpi label={ts.kpiDuration} value={formatDuration(durationS)} icon={Clock} />
        <Kpi label={ts.kpiMaxRisk} value={<RiskPill score={summary.max_score} showLabel className="h-8! px-2.5! text-lg!" />} icon={Gauge} />
        <Kpi label={ts.kpiRisky} value={events.data ? formatNumber(risky, locale) : "–"} hint={ts.kpiRiskyHint} icon={TriangleAlert} tone="var(--risk-medium)" />
        <Kpi label={ts.kpiWouldBlock} value={formatNumber(summary.would_block, locale)} hint={ts.kpiWouldBlockHint} icon={ShieldX} tone="var(--warn)" />
        <Kpi label={ts.kpiBlocked} value={formatNumber(summary.blocked, locale)} hint={ts.kpiBlockedHint} icon={Ban} tone="var(--danger)" alert={summary.blocked > 0} />
      </div>

      <AsyncView
        state={events}
        skeleton={<div className="space-y-4"><Skeleton className="h-96" /><Skeleton className="h-80" /></div>}
        isEmpty={(d) => d.length === 0}
        empty={<Card><EmptyState icon={ListTree} title={t.common.noData} body={ts.notFound} compact /></Card>}
      >
        {(rows) => (
          <>
            {rows.length >= EVENT_LIMIT && <Callout tone="warn">{fmt(ts.truncated, { n: formatNumber(EVENT_LIMIT, locale) })}</Callout>}
            <Card title={ts.timelineTitle} subtitle={ts.timelineHint}>
              <Timeline rows={asc} />
            </Card>
            <Card
              title={ts.eventsTitle}
              subtitle={fmt(t.common.eventsCount, { n: formatNumber(rows.length, locale) })}
              padded={false}
              actions={
                <Segmented
                  size="sm"
                  label={ts.orderLabel}
                  value={order}
                  onChange={setOrder}
                  options={[{ value: "asc", label: ts.orderAsc }, { value: "desc", label: ts.orderDesc }]}
                />
              }
            >
              <div className="mt-2 border-t border-line">
                <EventTable rows={ordered} columns={SESSION_COLUMNS} height={Math.min(460, 42 + rows.length * 42)} ariaLabel={ts.eventsLabel} />
              </div>
            </Card>
          </>
        )}
      </AsyncView>

      <ReplayDialog sessionId={id} open={replayOpen} onClose={() => setReplayOpen(false)} />
      <ConfirmDialog
        open={deleteOpen}
        danger
        busy={deleting}
        title={ts.deleteTitle}
        confirmLabel={ts.deleteConfirm}
        onConfirm={() => void remove()}
        onCancel={() => setDeleteOpen(false)}
      >
        <p>{fmt(ts.deleteBody, { n: formatNumber(summary.events, locale) })}</p>
        <code className="block rounded-md border border-line bg-bg-2 px-2.5 py-1.5 text-sm break-all text-fg">{id}</code>
        <p className="text-sm text-fg-3">{ts.deleteChainNote}</p>
      </ConfirmDialog>
    </div>
  );
}

// ------------------------------------------------------------------ page

export default function SessionsPage() {
  const t = useT();
  const ts = t.sessions;
  const locale = useLocale();
  const route = useRoute();
  const sessions = useAsync(() => backend.sessions(200), [], { refreshMs: 10_000 });
  const [filter, setFilter] = useState("");

  const paramId = route.params.get("id");
  const list = useMemo(() => sessions.data ?? [], [sessions.data]);
  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return list;
    return list.filter((s) => `${s.workspace ?? ""} ${s.session_id} ${s.agent}`.toLowerCase().includes(q));
  }, [list, filter]);
  // Without an explicit selection the most recent session is shown.
  const selected = (paramId ? list.find((s) => s.session_id === paramId) : list[0]) ?? null;

  return (
    <Page fill>
      <PageHeader icon={ListTree} title={ts.title} description={ts.description} />
      <div className="grid min-h-0 flex-1 grid-cols-[21rem_minmax(0,1fr)] gap-5">
        <Card padded={false} className="min-h-0 overflow-hidden" bodyClassName="flex flex-col">
          <div className="shrink-0 border-b border-line px-4 pt-3.5 pb-3">
            <div className="flex items-baseline justify-between gap-2">
              <h2 className="text-lg font-semibold text-fg">{ts.listTitle}</h2>
              {sessions.data && <span className="tabular text-sm text-fg-3">{fmt(ts.listCount, { n: formatNumber(visible.length, locale) })}</span>}
            </div>
            <div className="relative mt-2.5">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-3" aria-hidden />
              <input
                type="search"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder={ts.filterPlaceholder}
                aria-label={ts.filterLabel}
                spellCheck={false}
                className="h-9 w-full rounded-lg border border-line-strong bg-surface-2 pr-3 pl-9 text-base text-fg placeholder:text-fg-3 hover:border-fg-3 focus:border-focus focus:outline-none"
              />
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            <AsyncView
              state={sessions}
              skeleton={<div className="space-y-2 p-3">{[0, 1, 2, 3, 4, 5].map((i) => <Skeleton key={i} className="h-20" />)}</div>}
              isEmpty={(d) => d.length === 0}
              empty={<EmptyState icon={ListTree} title={ts.noSessions} body={ts.noSessionsBody} compact />}
            >
              {() => (visible.length === 0 ? <p className="px-4 py-6 text-center text-base text-fg-3">{ts.noMatch}</p> : (
                <div role="listbox" aria-label={ts.listLabel}>
                  {visible.map((s) => (
                    <SessionItem key={s.session_id} s={s} selected={s.session_id === selected?.session_id} onSelect={() => navigate("sessions", { id: s.session_id })} />
                  ))}
                </div>
              ))}
            </AsyncView>
          </div>
        </Card>

        <div className="min-h-0 min-w-0 overflow-y-auto pr-1 pb-6">
          {selected ? <SessionDetail key={selected.session_id} summary={selected} /> : sessions.loading ? <Spinner /> : sessions.error ? null : (
            <Card>
              <EmptyState
                icon={MousePointerClick}
                title={paramId && list.length > 0 ? t.common.noData : ts.selectTitle}
                body={paramId && list.length > 0 ? ts.notFound : ts.selectBody}
              />
            </Card>
          )}
        </div>
      </div>
    </Page>
  );
}
