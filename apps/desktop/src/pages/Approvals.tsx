import { useEffect, useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { CheckCircle2, CircleHelp, Hand, Hourglass, TerminalSquare, TriangleAlert, UserCheck, XCircle, type LucideIcon } from "lucide-react";
import { DecisionBadge, ModeBadge, RiskPill } from "../components/badges";
import { DataTable } from "../components/DataTable";
import { Page } from "../components/Page";
import { Badge, Callout, Card, EmptyState, ErrorState, Kpi, PageHeader, Segmented, Spinner } from "../components/ui";
import { useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { basename, formatDateTime, formatSmartTime } from "../lib/format";
import { useAsync, useLiveEvents, useNow } from "../lib/hooks";
import { useApp } from "../store/app";
import type { EventRow } from "../lib/types";

type AskState = "pending" | "approved" | "failed" | "rejected" | "unknown";
const STATES: AskState[] = ["pending", "approved", "failed", "rejected", "unknown"];
const PENDING_WINDOW_MS = 10 * 60_000;
const MAX_ROWS = 500;

const STATE_TONE: Record<AskState, string> = {
  pending: "var(--mode-interactive)",
  approved: "var(--ok)",
  failed: "var(--warn)",
  rejected: "var(--danger)",
  unknown: "var(--fg-3)",
};
const STATE_ICON: Record<AskState, LucideIcon> = {
  pending: Hourglass,
  approved: CheckCircle2,
  failed: TriangleAlert,
  rejected: XCircle,
  unknown: CircleHelp,
};

/** Derived ONLY from the recorded post-execution outcome; nothing is guessed. */
export function askState(row: EventRow, now: number): AskState {
  switch (row.observed_outcome) {
    case "executed": return "approved";
    case "failed": return "failed";
    case "blocked": return "rejected";
    default: return now - Date.parse(row.record.ts_utc) < PENDING_WINDOW_MS ? "pending" : "unknown";
  }
}

export default function ApprovalsPage() {
  const t = useT();
  const a = t.approvals;
  const locale = useLocale();
  const mode = useApp((s) => s.status?.mode);
  const openEvent = useApp((s) => s.openEvent);
  const now = useNow(15_000);
  const initial = useAsync(() => backend.listEvents({ actual_decision: "ask", limit: 300 }), []);
  const [rows, setRows] = useState<EventRow[]>([]);
  const [filter, setFilter] = useState<AskState | "all">("all");

  useEffect(() => {
    if (!initial.data) return;
    const loaded = initial.data;
    setRows((prev) => {
      const seen = new Set(loaded.map((r) => r.record.id));
      return [...prev.filter((r) => !seen.has(r.record.id)), ...loaded].sort((x, y) => y.record.id - x.record.id).slice(0, MAX_ROWS);
    });
  }, [initial.data]);

  useLiveEvents((row) => {
    const r = row.record;
    if (r.actual_decision === "ask") {
      setRows((prev) => (prev.some((p) => p.record.id === r.id) ? prev : [row, ...prev].slice(0, MAX_ROWS)));
    } else if (r.phase === "post" && r.correlation_id) {
      setRows((prev) => {
        const i = prev.findIndex((p) => p.record.correlation_id === r.correlation_id);
        const hit = prev[i];
        if (!hit || hit.observed_outcome === r.outcome) return prev;
        const next = prev.slice();
        next[i] = { ...hit, observed_outcome: r.outcome };
        return next;
      });
    }
  });

  const withState = useMemo(() => rows.map((row) => ({ row, state: askState(row, now) })), [rows, now]);
  const counts = useMemo(() => {
    const c: Record<AskState, number> = { pending: 0, approved: 0, failed: 0, rejected: 0, unknown: 0 };
    for (const r of withState) c[r.state]++;
    return c;
  }, [withState]);
  const visible = useMemo(() => (filter === "all" ? withState : withState.filter((r) => r.state === filter)), [withState, filter]);

  const columns = useMemo<ColumnDef<{ row: EventRow; state: AskState }>[]>(() => [
    {
      id: "time", header: t.common.time, accessorFn: (r) => r.row.record.ts_utc, meta: { className: "w-32 whitespace-nowrap" },
      cell: ({ row }) => <span className="tabular text-fg-2" title={formatDateTime(row.original.row.record.ts_utc, locale)}>{formatSmartTime(row.original.row.record.ts_utc, locale)}</span>,
    },
    {
      id: "project", header: t.common.project, accessorFn: (r) => basename(r.row.record.workspace), meta: { className: "w-40" },
      cell: ({ row }) => <span className="block max-w-40 truncate text-fg" title={row.original.row.record.workspace ?? ""}>{basename(row.original.row.record.workspace) || "–"}</span>,
    },
    {
      id: "action", header: t.common.action, enableSorting: false,
      cell: ({ row }) => {
        const r = row.original.row.record;
        return (
          <div className="max-w-xl min-w-0">
            <span className="block truncate font-mono text-sm text-fg" title={r.summary}>{r.summary}</span>
            {r.decision_reason && <span className="block truncate text-sm text-fg-3" title={r.decision_reason}>{r.decision_reason}</span>}
          </div>
        );
      },
    },
    {
      id: "risk", header: t.common.risk, accessorFn: (r) => r.row.record.risk.score, sortDescFirst: true, meta: { className: "w-20" },
      cell: ({ row }) => <RiskPill score={row.original.row.record.risk.score} />,
    },
    {
      id: "policy", header: a.colPolicy, accessorFn: (r) => r.row.record.simulated_decision, meta: { className: "w-32" },
      cell: ({ row }) => <DecisionBadge decision={row.original.row.record.simulated_decision} />,
    },
    {
      id: "mode", header: t.common.mode, accessorFn: (r) => r.row.record.mode, meta: { className: "w-36" },
      cell: ({ row }) => <ModeBadge mode={row.original.row.record.mode} />,
    },
    {
      id: "state", header: a.colState, accessorFn: (r) => STATES.indexOf(r.state), meta: { className: "w-60" },
      cell: ({ row }) => (
        <Badge tone={STATE_TONE[row.original.state]} icon={STATE_ICON[row.original.state]} title={a.stateHint[row.original.state]}>
          {a.state[row.original.state]}
        </Badge>
      ),
    },
  ], [t, a, locale]);

  const asks = mode === "interactive" || mode === "enforce";

  return (
    <Page>
      <PageHeader icon={UserCheck} title={a.title} description={a.description} />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Callout tone="info" icon={TerminalSquare} title={a.howTitle}>
          <ul className="mt-1.5 space-y-1.5">
            {[a.how1, a.how2, a.how3].map((line) => (
              <li key={line} className="flex gap-2.5"><span className="mt-2 size-1.5 shrink-0 rounded-full bg-info" aria-hidden />{line}</li>
            ))}
          </ul>
        </Callout>
        <Card>
          <div className="eyebrow mb-2">{a.modeTitle}</div>
          {mode ? (
            <>
              <ModeBadge mode={mode} size="lg" />
              <p className="mt-3 flex gap-2 text-base text-fg-2">
                <Hand className="mt-0.5 size-4 shrink-0" style={{ color: asks ? "var(--mode-interactive)" : "var(--fg-3)" }} aria-hidden />
                {asks ? a.modeAsksYes : mode === "lockdown" ? a.modeAsksLockdown : a.modeAsksNo}
              </p>
            </>
          ) : <Spinner />}
        </Card>
      </div>

      <div className="mt-5 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label={a.kpiTotal} value={rows.length} hint={a.kpiTotalHint} icon={Hand} tone="var(--mode-interactive)" />
        <Kpi label={a.kpiPending} value={counts.pending} hint={a.kpiPendingHint} icon={Hourglass} tone={STATE_TONE.pending} alert={counts.pending > 0} onClick={() => setFilter("pending")} />
        <Kpi label={a.kpiApproved} value={counts.approved} icon={CheckCircle2} tone={STATE_TONE.approved} onClick={() => setFilter("approved")} />
        <Kpi label={a.kpiFailed} value={counts.failed} icon={TriangleAlert} tone={STATE_TONE.failed} onClick={() => setFilter("failed")} />
        <Kpi label={a.kpiRejected} value={counts.rejected} icon={XCircle} tone={STATE_TONE.rejected} onClick={() => setFilter("rejected")} />
        <Kpi label={a.kpiUnknown} value={counts.unknown} hint={a.kpiUnknownHint} icon={CircleHelp} tone={STATE_TONE.unknown} onClick={() => setFilter("unknown")} />
      </div>

      <Card
        className="mt-5"
        title={a.listTitle}
        subtitle={a.listHint}
        padded={false}
        actions={
          <Segmented
            size="sm"
            label={a.stateFilter}
            value={filter}
            onChange={setFilter}
            options={[{ value: "all", label: t.common.all }, ...STATES.map((s) => ({ value: s, label: a.state[s] }))]}
          />
        }
      >
        {initial.error && rows.length === 0 ? <ErrorState error={initial.error} onRetry={initial.reload} compact />
          : initial.loading && rows.length === 0 ? <Spinner />
          : (
            <div className="pt-2">
              <DataTable
                ariaLabel={a.listTitle}
                data={visible}
                columns={columns}
                getRowId={(r) => String(r.row.record.id)}
                onRowClick={(r) => openEvent(r.row)}
                maxHeight={560}
                empty={<EmptyState icon={UserCheck} title={rows.length === 0 ? a.empty : a.emptyFiltered} body={rows.length === 0 ? a.emptyBody : undefined} compact />}
              />
            </div>
          )}
      </Card>
    </Page>
  );
}
