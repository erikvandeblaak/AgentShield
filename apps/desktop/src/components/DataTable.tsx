import { useState, type ReactNode } from "react";
import {
  flexRender, getCoreRowModel, getSortedRowModel, useReactTable, type ColumnDef, type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { EmptyState, cx } from "./ui";
import { useT } from "../i18n";

declare module "@tanstack/react-table" {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData, TValue> {
    /** Tailwind classes for both th and td (width, alignment). */
    className?: string;
    align?: "left" | "right";
  }
}

interface DataTableProps<T> {
  data: T[];
  columns: ColumnDef<T>[];
  onRowClick?: (row: T) => void;
  getRowId?: (row: T) => string;
  selectedId?: string | null;
  empty?: ReactNode;
  maxHeight?: number | string;
  dense?: boolean;
  ariaLabel: string;
  initialSort?: SortingState;
}

/** Sortable table for small/medium lists (TanStack Table). For event streams use EventTable (virtualised). */
export function DataTable<T>({ data, columns, onRowClick, getRowId, selectedId, empty, maxHeight, dense, ariaLabel, initialSort }: DataTableProps<T>) {
  const t = useT();
  const [sorting, setSorting] = useState<SortingState>(initialSort ?? []);
  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: getRowId ? (r) => getRowId(r) : undefined,
  });
  const rows = table.getRowModel().rows;
  return (
    <div className="min-w-0 overflow-auto" style={{ maxHeight }}>
      <table aria-label={ariaLabel} className="w-full border-collapse text-left text-base">
        <thead className="sticky top-0 z-10 bg-surface">
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id}>
              {hg.headers.map((h) => {
                const sorted = h.column.getIsSorted();
                const Icon = sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ChevronsUpDown;
                const meta = h.column.columnDef.meta;
                return (
                  <th
                    key={h.id}
                    scope="col"
                    aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : "none"}
                    className={cx("h-10 border-b border-line px-4 font-normal first:pl-5 last:pr-5", meta?.align === "right" && "text-right", meta?.className)}
                  >
                    {h.column.getCanSort() ? (
                      <button type="button" onClick={h.column.getToggleSortingHandler()} className={cx("eyebrow group inline-flex items-center gap-1 hover:text-fg", sorted && "text-fg")}>
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        <Icon className={cx("size-3", !sorted && "opacity-0 group-hover:opacity-70")} aria-hidden />
                      </button>
                    ) : (
                      <span className="eyebrow">{flexRender(h.column.columnDef.header, h.getContext())}</span>
                    )}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {rows.map((row) => {
            const selected = selectedId != null && row.id === selectedId;
            return (
              <tr
                key={row.id}
                tabIndex={onRowClick ? 0 : undefined}
                aria-selected={onRowClick ? selected : undefined}
                onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                onKeyDown={onRowClick ? (e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onRowClick(row.original);
                  }
                } : undefined}
                className={cx(
                  "border-b border-line/70 last:border-b-0",
                  onRowClick && "cursor-pointer transition-colors hover:bg-surface-2 focus-visible:bg-surface-2 focus-visible:outline-offset-[-2px]",
                  selected && "bg-surface-3 shadow-[inset_2px_0_0_var(--accent-2)]",
                )}
              >
                {row.getVisibleCells().map((cell) => {
                  const meta = cell.column.columnDef.meta;
                  return (
                    <td key={cell.id} className={cx("px-4 align-middle first:pl-5 last:pr-5", dense ? "py-2" : "py-2.5", meta?.align === "right" && "tabular text-right", meta?.className)}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
      {rows.length === 0 && (empty ?? <EmptyState title={t.common.noData} body={t.common.noDataBody} compact />)}
    </div>
  );
}
