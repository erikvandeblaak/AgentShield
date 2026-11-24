import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, FilterX, Inbox, Pause, Play, Search } from "lucide-react";
import { EventTable } from "../components/EventTable";
import { Page } from "../components/Page";
import { Button, Callout, EmptyState, PageHeader, Select, cx, type Option } from "../components/ui";
import { fmt, useT } from "../i18n";
import { backend } from "../lib/backend";
import { useDebounced } from "../lib/hooks";
import { navigate, useRoute } from "../lib/router";
import { useApp } from "../store/app";
import { LIVE_MAX, useLive } from "../store/live";
import { ALL_CATEGORIES } from "../theme/palette";
import type { ActualDecision, EventQuery, EventRow, Phase, PolicyDecision, RiskCategory } from "../lib/types";

export const EVENT_TYPES = [
  "shell.exec", "file.read", "file.write", "file.edit", "file.search", "network.fetch", "network.search", "mcp.call",
  "agent.subagent", "agent.prompt", "session.start", "session.end", "agent.notification", "agent.stop",
  "agent.permission_request", "agent.permission_denied", "agentshield.mode_change", "tool.other",
] as const;

interface Filters {
  search: string;
  min: string; // "", "20", "40", "60", "80"
  decision: string; // "", "sim:<PolicyDecision>", "act:<ActualDecision>"
  action: string;
  category: string;
  phase: string;
}

const EMPTY: Filters = { search: "", min: "", decision: "", action: "", category: "", phase: "" };

function fromParams(p: URLSearchParams): Filters {
  const sim = p.get("decision");
  const act = p.get("actual");
  return {
    search: p.get("q") ?? "",
    min: p.get("min") && p.get("min") !== "0" ? (p.get("min") ?? "") : "",
    decision: sim ? `sim:${sim}` : act ? `act:${act}` : "",
    action: p.get("action") ?? "",
    category: p.get("category") ?? "",
    phase: p.get("phase") ?? "",
  };
}

function toQuery(f: Filters): EventQuery {
  const q: EventQuery = {};
  if (f.search.trim()) q.search = f.search.trim();
  if (f.min) q.min_score = Number(f.min);
  if (f.decision.startsWith("sim:")) q.simulated_decision = f.decision.slice(4) as PolicyDecision;
  if (f.decision.startsWith("act:")) q.actual_decision = f.decision.slice(4) as ActualDecision;
  if (f.action) q.action_type = f.action;
  if (f.category) q.category = f.category as RiskCategory;
  if (f.phase) q.phase = f.phase as Phase;
  return q;
}

/** Client-side equivalent of the backend filter, applied to rows already in the live buffer. */
function matches(row: EventRow, q: EventQuery): boolean {
  const r = row.record;
  if (q.min_score != null && r.risk.score < q.min_score) return false;
  if (q.simulated_decision && (r.simulated_decision !== q.simulated_decision || r.phase !== "pre")) return false;
  if (q.actual_decision && r.actual_decision !== q.actual_decision) return false;
  if (q.action_type && r.action_type !== q.action_type) return false;
  if (q.category && !r.risk.categories.includes(q.category)) return false;
  if (q.phase && r.phase !== q.phase) return false;
  if (q.search) {
    const needle = q.search.toLowerCase();
    const hay = `${r.summary} ${r.tool ?? ""} ${r.action_type} ${r.workspace ?? ""} ${r.session_id ?? ""} ${r.matched_rules.join(" ")} ${r.risk.findings.map((x) => x.id).join(" ")}`.toLowerCase();
    if (!hay.includes(needle)) return false;
  }
  return true;
}

const PAGE = 300;

export default function LivePage() {
  const t = useT();
  const l = t.live;
  const route = useRoute();
  const buffer = useLive((s) => s.rows);
  const monitoringPaused = useApp((s) => s.status?.paused ?? false);

  const [filters, setFilters] = useState<Filters>(() => fromParams(route.params));
  const paramKey = route.params.toString();
  useEffect(() => setFilters(fromParams(new URLSearchParams(paramKey))), [paramKey]);
  const set = (patch: Partial<Filters>) => setFilters((f) => ({ ...f, ...patch }));
  const debouncedSearch = useDebounced(filters.search, 250);
  const query = useMemo(() => toQuery({ ...filters, search: debouncedSearch }), [filters, debouncedSearch]);
  const queryKey = JSON.stringify(query);
  const active = queryKey !== "{}";

  // Pause freezes the view on a snapshot; the ring buffer keeps filling in the background.
  const [frozen, setFrozen] = useState<EventRow[] | null>(null);
  const source = frozen ?? buffer;
  const waiting = frozen ? (frozen[0] ? buffer.findIndex((r) => r.record.id <= (frozen[0] as EventRow).record.id) : buffer.length) : 0;
  const waitingCount = waiting < 0 ? buffer.length : waiting;

  // Older history (beyond the buffer) for the current filter, fetched on demand via before_id.
  const [older, setOlder] = useState<EventRow[]>([]);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [exhausted, setExhausted] = useState(false);
  const [olderError, setOlderError] = useState<string | null>(null);
  const epoch = useApp((s) => s.epoch);
  useEffect(() => {
    setOlder([]);
    setExhausted(false);
    setOlderError(null);
  }, [queryKey, epoch]);

  const visible = useMemo(() => {
    const fromBuffer = active ? source.filter((r) => matches(r, query)) : source;
    return older.length ? fromBuffer.concat(older) : fromBuffer;
  }, [source, older, query, active]);

  const inFlight = useRef(false);
  const loadOlder = useCallback(() => {
    if (inFlight.current || exhausted || source.length === 0) return;
    const oldestBuffer = (source[source.length - 1] as EventRow).record.id;
    const before = older.length ? (older[older.length - 1] as EventRow).record.id : oldestBuffer;
    if (before <= 1) {
      setExhausted(true);
      return;
    }
    inFlight.current = true;
    setLoadingOlder(true);
    const key = queryKey;
    backend.listEvents({ ...query, before_id: before, limit: PAGE })
      .then((rows) => {
        if (key !== queryKey) return;
        if (rows.length < PAGE) setExhausted(true);
        if (rows.length) setOlder((o) => o.concat(rows));
        setOlderError(null);
      })
      .catch((e: unknown) => setOlderError(typeof e === "string" ? e : String(e)))
      .finally(() => {
        inFlight.current = false;
        setLoadingOlder(false);
      });
  }, [exhausted, source, older, query, queryKey]);

  // With filters active the buffer may hold few matches: pull history right away.
  useEffect(() => {
    if (active && visible.length < 40 && !exhausted && source.length > 0) loadOlder();
  }, [active, visible.length, exhausted, source.length, loadOlder]);

  // Highlight rows that arrived after the page opened.
  const baseline = useRef<number | null>(null);
  if (baseline.current === null && buffer.length > 0) baseline.current = (buffer[0] as EventRow).record.id;

  const minOptions: Option<string>[] = [{ value: "", label: l.minAny }, ...["20", "40", "60", "80"].map((n) => ({ value: n, label: `${t.common.risk} ${fmt(l.minN, { n })}` }))];
  const decisionOptions: Option<string>[] = [
    { value: "", label: l.decisionAny },
    ...(["warn", "ask", "require_sandbox", "deny"] as const).map((d) => ({ value: `sim:${d}`, label: `${l.groupPolicy}: ${t.enums.decision[d].toLowerCase()}` })),
    ...(["ask", "deny"] as const).map((d) => ({ value: `act:${d}`, label: `${l.groupActual}: ${t.enums.actual[d].toLowerCase()}` })),
  ];
  const actionOptions: Option<string>[] = [{ value: "", label: l.actionAny }, ...EVENT_TYPES.map((e) => ({ value: e, label: e }))];
  const categoryOptions: Option<string>[] = [{ value: "", label: l.categoryAny }, ...ALL_CATEGORIES.map((c) => ({ value: c, label: t.enums.category[c] }))];
  const phaseOptions: Option<string>[] = [{ value: "", label: l.phaseAny }, ...(["pre", "post", "lifecycle"] as const).map((p) => ({ value: p, label: t.enums.phaseLong[p] }))];

  const clear = () => {
    setFilters(EMPTY);
    if (paramKey) navigate("live");
  };

  return (
    <Page fill>
      <PageHeader
        title={l.title}
        description={l.description}
        icon={Activity}
        actions={
          <>
            <span className="flex h-9.5 items-center gap-2 rounded-lg border border-line bg-surface px-3 text-sm text-fg-2" role="status">
              <span className={cx("size-2 rounded-full", frozen || monitoringPaused ? "bg-warn" : "animate-pulse-dot bg-ok text-ok")} aria-hidden />
              {frozen || monitoringPaused ? l.paused : l.streaming}
            </span>
            {frozen ? (
              <Button variant="primary" icon={Play} onClick={() => setFrozen(null)}>{waitingCount > 0 ? fmt(l.resumeWithCount, { n: waitingCount }) : l.resume}</Button>
            ) : (
              <Button icon={Pause} onClick={() => setFrozen(buffer)}>{l.pause}</Button>
            )}
          </>
        }
      />

      {monitoringPaused && <Callout tone="warn" className="mb-4">{l.monitoringPaused}</Callout>}

      <div className="flex min-h-0 flex-1 flex-col rounded-xl border border-line bg-surface shadow-card">
        <div className="flex flex-wrap items-center gap-2.5 border-b border-line p-3">
          <div className="relative min-w-52 flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-3" aria-hidden />
            <input
              type="search"
              value={filters.search}
              onChange={(e) => set({ search: e.target.value })}
              placeholder={l.searchPlaceholder}
              aria-label={l.searchLabel}
              spellCheck={false}
              className="h-9.5 w-full rounded-lg border border-line-strong bg-surface-2 pr-3 pl-9 text-base text-fg placeholder:text-fg-3 hover:border-fg-3 focus:border-focus focus:outline-none"
            />
          </div>
          <Select className="w-32" aria-label={l.minScore} value={filters.min} onChange={(min) => set({ min })} options={minOptions} />
          <Select className="w-48" aria-label={l.decision} value={filters.decision} onChange={(decision) => set({ decision })} options={decisionOptions} />
          <Select className="w-40" aria-label={l.actionType} value={filters.action} onChange={(action) => set({ action })} options={actionOptions} />
          <Select className="w-48" aria-label={l.category} value={filters.category} onChange={(category) => set({ category })} options={categoryOptions} />
          <Select className="w-36" aria-label={l.phase} value={filters.phase} onChange={(phase) => set({ phase })} options={phaseOptions} />
          {(active || filters.search) && <Button variant="ghost" icon={FilterX} onClick={clear}>{t.common.clearFilters}</Button>}
        </div>

        {frozen && waitingCount > 0 && (
          <div role="status" className="flex items-center justify-between gap-3 border-b border-line bg-warn/8 px-4 py-2 text-sm text-fg-2">
            <span>{fmt(l.pausedNote, { n: waitingCount })}</span>
            <button type="button" className="font-semibold text-fg underline-offset-4 hover:underline" onClick={() => setFrozen(null)}>{l.resume}</button>
          </div>
        )}

        <div className="min-h-0 flex-1">
          <EventTable
            rows={visible}
            height="100%"
            ariaLabel={l.tableAria}
            onEndReached={loadOlder}
            highlightAfterId={frozen ? undefined : (baseline.current ?? undefined)}
            empty={
              active
                ? <EmptyState icon={FilterX} title={l.emptyFiltered} body={l.emptyFilteredBody} action={<Button onClick={clear}>{t.common.clearFilters}</Button>} />
                : <EmptyState icon={Inbox} title={l.emptyTitle} body={l.emptyBody} />
            }
            footer={
              visible.length === 0 ? null
                : olderError ? <span className="text-danger">{olderError} · <button type="button" className="underline" onClick={loadOlder}>{t.common.retry}</button></span>
                : loadingOlder ? t.common.loadingMore
                : exhausted ? t.common.endOfList
                : <button type="button" className="font-medium text-fg-2 underline-offset-4 hover:text-fg hover:underline" onClick={loadOlder}>{t.common.loadMore}</button>
            }
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 border-t border-line px-4 py-2 text-sm text-fg-3">
          <span className="tabular">
            {fmt(l.shown, { shown: visible.length - older.length, total: source.length })}
            {older.length > 0 && <span> · {fmt(l.olderLoaded, { n: older.length })}</span>}
          </span>
          <span>{fmt(l.bufferNote, { max: LIVE_MAX })}</span>
        </div>
      </div>
    </Page>
  );
}
