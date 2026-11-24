import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Boxes, Fingerprint, FolderGit2, KeyRound, ShieldQuestion, X } from "lucide-react";
import { CategoryChip, RiskPill } from "../components/badges";
import { CENTER_COLUMNS, KpiGrid, ProjectChips, withoutPost } from "../components/centers/shared";
import { summariseSecrets, type FindingGroup, type FingerprintGroup } from "../components/centers/secrets";
import { DataTable } from "../components/DataTable";
import { EventTable } from "../components/EventTable";
import { Page } from "../components/Page";
import { AsyncView, Badge, Button, Callout, Card, EmptyState, Kpi, PageHeader } from "../components/ui";
import { fmt, useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { formatNumber, formatSmartTime } from "../lib/format";
import { useAsync } from "../lib/hooks";
import type { EventRow } from "../lib/types";

function SecretsView({ rows }: { rows: EventRow[] }) {
  const t = useT();
  const s = t.secrets;
  const locale = useLocale();
  const [selected, setSelected] = useState<string | null>(null);
  const summary = useMemo(() => summariseSecrets(rows), [rows]);
  const active = summary.fingerprints.find((f) => f.key === selected) ?? null;
  const shown = useMemo(() => (active ? rows.filter((r) => active.eventIds.has(r.record.id)) : rows), [rows, active]);

  const fpColumns = useMemo<ColumnDef<FingerprintGroup>[]>(() => [
    { id: "kind", header: s.colKind, accessorFn: (g) => g.kind, cell: ({ row }) => <Badge tone="var(--series-4)">{row.original.kind}</Badge> },
    { id: "fp", header: s.colFingerprint, accessorFn: (g) => g.fingerprint, cell: ({ row }) => <code className="text-sm text-fg">{row.original.fingerprint}</code> },
    { id: "count", header: s.colOccurrences, accessorFn: (g) => g.count, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => formatNumber(row.original.count, locale) },
    { id: "first", header: s.colFirstSeen, accessorFn: (g) => g.first, cell: ({ row }) => <span className="tabular text-fg-2">{formatSmartTime(row.original.first, locale)}</span> },
    { id: "last", header: s.colLastSeen, accessorFn: (g) => g.last, cell: ({ row }) => <span className="tabular text-fg-2">{formatSmartTime(row.original.last, locale)}</span> },
    { id: "projects", header: s.colProjects, accessorFn: (g) => g.workspaces.length, cell: ({ row }) => <ProjectChips workspaces={row.original.workspaces} /> },
    { id: "max", header: s.colMaxScore, accessorFn: (g) => g.maxScore, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => <RiskPill score={row.original.maxScore} /> },
  ], [s, locale]);

  const findingColumns = useMemo<ColumnDef<FindingGroup>[]>(() => [
    {
      id: "id", header: s.colFindingId, accessorFn: (g) => g.id,
      cell: ({ row }) => (
        <div className="min-w-0">
          <code className="text-sm font-medium text-fg">{row.original.id}</code>
          <div className="mt-0.5 line-clamp-2 text-sm text-fg-3">{row.original.explanation}</div>
        </div>
      ),
    },
    { id: "cat", header: t.common.category, accessorFn: (g) => g.category, cell: ({ row }) => <CategoryChip category={row.original.category} /> },
    { id: "count", header: t.common.count, accessorFn: (g) => g.count, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => formatNumber(row.original.count, locale) },
    { id: "max", header: s.colMaxScore, accessorFn: (g) => g.maxScore, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => <RiskPill score={row.original.maxScore} /> },
  ], [s, t, locale]);

  return (
    <>
      <KpiGrid>
        <Kpi label={s.kpiEvents} value={formatNumber(rows.length, locale)} hint={s.kpiEventsHint} icon={KeyRound} tone="var(--series-4)" />
        <Kpi label={s.kpiFingerprints} value={formatNumber(summary.fingerprints.length, locale)} hint={s.kpiFingerprintsHint} icon={Fingerprint} tone="var(--accent-2)" />
        <Kpi label={s.kpiKinds} value={formatNumber(summary.kinds, locale)} hint={s.kpiKindsHint} icon={Boxes} tone="var(--accent-3)" />
        <Kpi label={s.kpiProjects} value={formatNumber(summary.projects, locale)} hint={s.kpiProjectsHint} icon={FolderGit2} />
      </KpiGrid>

      <div className="grid grid-cols-1 gap-5 min-[1900px]:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Card title={s.byFingerprint} subtitle={s.byFingerprintHint} padded={false} bodyClassName="pt-2">
          <DataTable
            ariaLabel={s.tableFingerprints}
            data={summary.fingerprints}
            columns={fpColumns}
            getRowId={(g) => g.key}
            selectedId={selected}
            onRowClick={(g) => setSelected((cur) => (cur === g.key ? null : g.key))}
            maxHeight={340}
            dense
            empty={<EmptyState icon={Fingerprint} title={s.noFingerprints} body={s.noFingerprintsBody} compact />}
          />
        </Card>
        <Card title={s.byFinding} subtitle={s.byFindingHint} padded={false} bodyClassName="pt-2">
          <DataTable ariaLabel={s.tableFindings} data={summary.findings} columns={findingColumns} getRowId={(g) => g.id} maxHeight={340} dense />
        </Card>
      </div>

      <Card
        className="mt-5"
        title={s.eventsTitle}
        subtitle={s.eventsHint}
        padded={false}
        bodyClassName="pt-2"
        actions={
          active ? (
            <>
              <span className="flex items-center gap-2 text-sm text-fg-2">
                {s.filteredBy}
                <Badge tone="var(--accent-2)" icon={Fingerprint}><code>{active.kind}:{active.fingerprint}</code></Badge>
              </span>
              <Button size="sm" variant="ghost" icon={X} onClick={() => setSelected(null)}>{s.clearFilter}</Button>
            </>
          ) : (
            <span className="tabular text-sm text-fg-3">
              {fmt(t.common.eventsCount, { n: formatNumber(shown.length, locale) })}
              {summary.withoutFingerprint > 0 && <> · {fmt(s.withoutFingerprint, { n: formatNumber(summary.withoutFingerprint, locale) })}</>}
            </span>
          )
        }
      >
        <EventTable ariaLabel={s.tableEvents} rows={shown} columns={CENTER_COLUMNS} height={Math.min(460, 44 + Math.max(3, shown.length) * 42)} />
      </Card>

      <Callout tone="info" icon={ShieldQuestion} title={s.explainerTitle} className="mt-5">
        <ul className="mt-1 list-disc space-y-1 pl-4.5">
          <li>{s.explainer1}</li>
          <li>{s.explainer2}</li>
          <li>{s.explainer3}</li>
          <li>{s.explainer4}</li>
        </ul>
      </Callout>
    </>
  );
}

export default function SecretsPage() {
  const t = useT();
  const state = useAsync(() => backend.listEvents({ secrets_only: true, limit: 1000 }).then(withoutPost), [], { refreshMs: 15000 });
  return (
    <Page>
      <PageHeader title={t.secrets.title} description={t.secrets.description} icon={KeyRound} />
      <AsyncView
        state={state}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <>
            <Card><EmptyState icon={KeyRound} title={t.secrets.emptyTitle} body={t.secrets.emptyBody} /></Card>
            <Callout tone="info" icon={ShieldQuestion} title={t.secrets.explainerTitle} className="mt-5">
              <ul className="mt-1 list-disc space-y-1 pl-4.5">
                <li>{t.secrets.explainer1}</li>
                <li>{t.secrets.explainer2}</li>
                <li>{t.secrets.explainer3}</li>
              </ul>
            </Callout>
          </>
        }
      >
        {(rows) => <SecretsView rows={rows} />}
      </AsyncView>
    </Page>
  );
}
