import type { ReactNode } from "react";
import type { EventColumnId } from "../EventTable";
import { basename } from "../../lib/format";
import type { EventRow } from "../../lib/types";

/** Columns used by the event lists in the centers (narrower than Live Activity). */
export const CENTER_COLUMNS: EventColumnId[] = ["time", "project", "session", "action", "risk", "simulated", "actual", "outcome"];
export const CENTER_COLUMNS_PHASE: EventColumnId[] = ["time", "project", "phase", "action", "risk", "simulated", "actual", "outcome"];

export function KpiGrid({ children, cols = 4 }: { children: ReactNode; cols?: 4 | 5 }) {
  return (
    <div className={cols === 5 ? "mb-5 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5" : "mb-5 grid grid-cols-2 gap-4 xl:grid-cols-4"}>
      {children}
    </div>
  );
}

/** Compact list of project (workspace basename) chips, with the full paths in the tooltip. */
export function ProjectChips({ workspaces, max = 1 }: { workspaces: string[]; max?: number }) {
  if (workspaces.length === 0) return <span className="text-fg-3">–</span>;
  const shown = workspaces.slice(0, max);
  return (
    <span className="flex min-w-0 items-center gap-1 whitespace-nowrap" title={workspaces.join("\n")}>
      {shown.map((w) => (
        <span key={w} className="max-w-32 truncate rounded-md border border-line bg-surface-2 px-1.5 py-0.5 text-xs text-fg-2">{basename(w)}</span>
      ))}
      {workspaces.length > max && <span className="tabular text-xs text-fg-3">+{workspaces.length - max}</span>}
    </span>
  );
}

/** Rows that represent an action once: pre and lifecycle events (post events repeat the pre event's assessment). */
export function withoutPost(rows: EventRow[]): EventRow[] {
  return rows.filter((r) => r.record.phase !== "post");
}

export function maxIso(a: string, b: string): string {
  return a > b ? a : b;
}

export function minIso(a: string, b: string): string {
  return a < b ? a : b;
}
