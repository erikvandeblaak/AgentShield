import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  flexRender, getCoreRowModel, getSortedRowModel, useReactTable, type ColumnDef, type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { ActualBadge, ConfidenceBadge, DecisionBadge, OutcomeBadge, PhaseBadge, RiskPill } from "./badges";
import { EmptyState, cx } from "./ui";
import { fmt, useLocale, useT, type Dict } from "../i18n";
import { basename, effectiveOutcome, formatDateTime, formatSmartTime, shortId } from "../lib/format";
import { useApp } from "../store/app";
import type { EventRow } from "../lib/types";

export type EventColumnId =
  | "time" | "agent" | "project" | "session" | "action" | "tool" | "phase" | "risk" | "confidence"
  | "actual" | "simulated" | "outcome" | "policy";

export const FULL_COLUMNS: EventColumnId[] = [
  "time", "agent", "project", "session", "action", "tool", "risk", "confidence", "actual", "simulated", "outcome", "policy",
];
export const COMPACT_COLUMNS: EventColumnId[] = ["time", "project", "action", "risk", "simulated", "actual", "outcome"];

const WIDTH: Record<EventColumnId, string> = {
  time: "78px", agent: "88px", project: "112px", session: "76px", action: "minmax(170px,1fr)", tool: "68px", phase: "64px",
  risk: "48px", confidence: "100px", actual: "92px", simulated: "108px", outcome: "100px", policy: "112px",
};

const LEVEL_ORDER = { low: 0, medium: 1, high: 2 } as const;
const DECISION_ORDER = { allow: 0, warn: 1, ask: 2, require_sandbox: 3, deny: 4 } as const;

function buildColumns(t: Dict, locale: string): Record<EventColumnId, ColumnDef<EventRow>> {
  const muted = (s: string | null | undefined) => (s ? <span className="block truncate text-fg-2" title={s}>{s}</span> : <span className="text-fg-3">–</span>);
  return {
    time: {
      id: "time", header: t.common.time, accessorFn: (r) => r.record.ts_utc,
      cell: ({ row }) => <span className="tabular text-fg-2" title={formatDateTime(row.original.record.ts_utc, locale)}>{formatSmartTime(row.original.record.ts_utc, locale)}</span>,
    },
    agent: { id: "agent", header: t.common.agent, accessorFn: (r) => r.record.agent, cell: ({ row }) => muted(row.original.record.agent) },
    project: {
      id: "project", header: t.common.project, accessorFn: (r) => basename(r.record.workspace),
      cell: ({ row }) => {
        const ws = row.original.record.workspace;
        return ws ? <span className="block truncate text-fg" title={ws}>{basename(ws)}</span> : <span className="text-fg-3">–</span>;
      },
    },
    session: {
      id: "session", header: t.common.session, accessorFn: (r) => r.record.session_id ?? "",
      cell: ({ row }) => {
        const s = row.original.record.session_id;
        return s ? <code className="text-sm text-fg-2" title={s}>{shortId(s.replace(/^demo-/, ""), 7)}</code> : <span className="text-fg-3">–</span>;
      },
    },
    action: {
      id: "action", header: t.common.action, accessorFn: (r) => r.record.summary, enableSorting: false,
      cell: ({ row }) => {
        const r = row.original.record;
        return (
          <span className="flex min-w-0 items-center gap-2">
            <span className="hidden shrink-0 rounded border border-line bg-surface-2 px-1.5 py-px font-mono text-xs text-fg-3 min-[1800px]:inline">{r.action_type}</span>
            <span className="truncate font-mono text-sm text-fg" title={r.summary}>{r.summary}</span>
          </span>
        );
      },
    },
    tool: { id: "tool", header: t.common.tool, accessorFn: (r) => r.record.tool ?? "", cell: ({ row }) => muted(row.original.record.tool) },
    phase: { id: "phase", header: t.common.phase, accessorFn: (r) => r.record.phase, cell: ({ row }) => <PhaseBadge phase={row.original.record.phase} /> },
    risk: {
      id: "risk", header: t.common.risk, accessorFn: (r) => r.record.risk.score, sortDescFirst: true,
      cell: ({ row }) => <RiskPill score={row.original.record.risk.score} />,
    },
    confidence: {
      id: "confidence", header: t.common.confidence, accessorFn: (r) => LEVEL_ORDER[r.record.risk.confidence] ?? 0,
      cell: ({ row }) => (row.original.record.risk.findings.length ? <ConfidenceBadge confidence={row.original.record.risk.confidence} /> : <span className="text-fg-3">–</span>),
    },
    actual: {
      id: "actual", header: t.common.colActual, accessorFn: (r) => r.record.actual_decision,
      cell: ({ row }) => <ActualBadge decision={row.original.record.actual_decision} />,
    },
    simulated: {
      id: "simulated", header: t.common.colSimulated, accessorFn: (r) => DECISION_ORDER[r.record.simulated_decision] ?? 0, sortDescFirst: true,
      cell: ({ row }) => (row.original.record.phase === "pre" ? <DecisionBadge decision={row.original.record.simulated_decision} simulated={row.original.record.actual_decision === "no_opinion"} /> : <span className="text-fg-3">–</span>),
    },
    outcome: {
      id: "outcome", header: t.common.colOutcome, accessorFn: (r) => effectiveOutcome(r),
      cell: ({ row }) => <OutcomeBadge outcome={effectiveOutcome(row.original)} />,
    },
    policy: {
      id: "policy", header: t.common.colPolicy, accessorFn: (r) => r.record.matched_rules[0] ?? "", enableSorting: false,
      cell: ({ row }) => {
        const rules = row.original.record.matched_rules;
        if (rules.length === 0) return <span className="text-fg-3">–</span>;
        return (
          <span className="flex min-w-0 items-center gap-1.5" title={rules.join("\n")}>
            <code className="truncate text-sm text-fg-2">{rules[0]}</code>
            {rules.length > 1 && <span className="tabular shrink-0 rounded bg-surface-3 px-1 text-xs text-fg-2">+{rules.length - 1}</span>}
          </span>
        );
      },
    },
  };
}

interface EventTableProps {
  rows: EventRow[];
  columns?: EventColumnId[];
  /** Fixed pixel height or any CSS length. The table scrolls inside it. */
  height?: number | string;
  onRowClick?: (row: EventRow) => void;
  /** Called when the user scrolls near the end (infinite scroll backwards). */
  onEndReached?: () => void;
  footer?: ReactNode;
  empty?: ReactNode;
  /** Briefly highlight rows with an id greater than this (new live rows). */
  highlightAfterId?: number;
  ariaLabel: string;
}

const ROW_H = 42;

/** Virtualised, sortable event table (TanStack Table + TanStack Virtual). Rows open the detail panel. */
export function EventTable({ rows, columns = FULL_COLUMNS, height = 520, onRowClick, onEndReached, footer, empty, highlightAfterId, ariaLabel }: EventTableProps) {
  const t = useT();
  const locale = useLocale();
  const openEvent = useApp((s) => s.openEvent);
  const selectedId = useApp((s) => s.detail?.record.id ?? null);
  const [sorting, setSorting] = useState<SortingState>([]);
  const defs = useMemo(() => {
    const all = buildColumns(t, locale);
    return columns.map((c) => all[c]);
  }, [t, locale, columns]);

  const table = useReactTable({
    data: rows,
    columns: defs,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (r) => String(r.record.id),
  });
  const model = table.getRowModel().rows;

  const scroller = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({
    count: model.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_H,
    overscan: 14,
  });
  const items = virt.getVirtualItems();
  const lastIndex = items[items.length - 1]?.index ?? 0;
  const endRef = useRef(onEndReached);
  endRef.current = onEndReached;
  useEffect(() => {
    if (model.length > 0 && lastIndex >= model.length - 12) endRef.current?.();
  }, [lastIndex, model.length]);

  const template = columns.map((c) => WIDTH[c]).join(" ");
  const click = onRowClick ?? openEvent;

  return (
    <div role="table" aria-label={ariaLabel} aria-rowcount={model.length} className="flex min-w-0 flex-col" style={{ height }}>
      <div ref={scroller} className="min-h-0 flex-1 overflow-auto">
        <div className="min-w-max">
          <div role="row" className="sticky top-0 z-10 grid h-10 items-center gap-x-2 border-b border-line bg-surface px-3" style={{ gridTemplateColumns: template }}>
            {table.getHeaderGroups()[0]?.headers.map((h) => {
              const sorted = h.column.getIsSorted();
              const can = h.column.getCanSort();
              const Icon = sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ChevronsUpDown;
              return (
                <div key={h.id} role="columnheader" aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : "none"} className="min-w-0">
                  {can ? (
                    <button type="button" onClick={h.column.getToggleSortingHandler()} className={cx("eyebrow group flex max-w-full items-center gap-1 hover:text-fg", sorted && "text-fg")}>
                      <span className="truncate">{flexRender(h.column.columnDef.header, h.getContext())}</span>
                      <Icon className={cx("size-3 shrink-0", !sorted && "opacity-0 group-hover:opacity-70")} aria-hidden />
                    </button>
                  ) : (
                    <span className="eyebrow block truncate">{flexRender(h.column.columnDef.header, h.getContext())}</span>
                  )}
                </div>
              );
            })}
          </div>
          {model.length === 0 ? (
            <div>{empty ?? <EmptyState title={t.common.noResults} body={t.common.noResultsBody} compact />}</div>
          ) : (
            <div role="rowgroup" className="relative" style={{ height: virt.getTotalSize() }}>
              {items.map((vi) => {
                const row = model[vi.index];
                if (!row) return null;
                const rec = row.original.record;
                const selected = rec.id === selectedId;
                const fresh = highlightAfterId != null && rec.id > highlightAfterId;
                return (
                  <div
                    key={row.id}
                    role="row"
                    aria-rowindex={vi.index + 1}
                    aria-selected={selected}
                    aria-label={fmt(t.shell.detail.title, { id: rec.id })}
                    tabIndex={0}
                    onClick={() => click(row.original)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        click(row.original);
                      }
                    }}
                    className={cx(
                      "absolute right-0 left-0 grid cursor-pointer items-center gap-x-2 border-b border-line/70 px-3 text-base transition-colors",
                      "hover:bg-surface-2 focus-visible:bg-surface-2 focus-visible:outline-offset-[-2px]",
                      selected && "bg-surface-3 shadow-[inset_2px_0_0_var(--accent-2)]",
                      fresh && !selected && "animate-row-in",
                    )}
                    style={{ height: ROW_H, transform: `translateY(${vi.start}px)`, gridTemplateColumns: template }}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <div key={cell.id} role="cell" className="min-w-0">{flexRender(cell.column.columnDef.cell, cell.getContext())}</div>
                    ))}
                  </div>
                );
              })}
            </div>
          )}
          {footer && <div className="px-4 py-3 text-center text-sm text-fg-3">{footer}</div>}
        </div>
      </div>
    </div>
  );
}
