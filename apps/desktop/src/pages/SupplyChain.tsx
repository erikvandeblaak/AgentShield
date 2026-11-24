import { useMemo } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { CloudOff, Download, Lightbulb, Package, PackageSearch, Replace, SpellCheck, Zap } from "lucide-react";
import { CategoryChip, ConfidenceBadge, RiskPill } from "../components/badges";
import { parsePackages, supplyKind, type PackageAction, type SupplyKind } from "../components/centers/packages";
import { CENTER_COLUMNS, KpiGrid, ProjectChips, maxIso, withoutPost } from "../components/centers/shared";
import { DataTable } from "../components/DataTable";
import { EventTable } from "../components/EventTable";
import { Page } from "../components/Page";
import { AsyncView, Badge, Callout, Card, EmptyState, Kpi, PageHeader } from "../components/ui";
import { fmt, useLocale, useT, type Dict } from "../i18n";
import { backend } from "../lib/backend";
import { formatNumber, formatSmartTime } from "../lib/format";
import { useAsync } from "../lib/hooks";
import { useApp } from "../store/app";
import type { Confidence, EventRow, Finding, RiskCategory } from "../lib/types";

interface PackageGroup {
  key: string;
  manager: string;
  name: string;
  action: PackageAction;
  count: number;
  last: string;
  lastRow: EventRow;
  maxScore: number;
  topFinding: string | null;
  workspaces: string[];
}

interface FindingGroup {
  id: string;
  kind: SupplyKind;
  category: RiskCategory;
  confidence: Confidence;
  count: number;
  maxScore: number;
  explanation: string;
  mitigation: string | null;
  packages: string[];
}

const SUPPLY_CATEGORIES = new Set<RiskCategory>(["supply_chain_compromise", "suspicious_package_installation"]);

function isSupplyFinding(f: Finding): boolean {
  return SUPPLY_CATEGORIES.has(f.category) || f.id.startsWith("package.") || supplyKind(f.id) !== "other";
}

function summarise(rows: EventRow[]) {
  const packages = new Map<string, PackageGroup & { ws: Set<string> }>();
  const findings = new Map<string, FindingGroup & { pk: Set<string> }>();
  const kinds: Record<SupplyKind, number> = { typosquat: 0, registry: 0, remote: 0, scripts: 0, other: 0 };
  for (const row of rows) {
    const r = row.record;
    const refs = r.action.type === "shell_exec" ? parsePackages(r.action.command) : [];
    const supplyFindings = r.risk.findings.filter(isSupplyFinding);
    const top = [...supplyFindings].sort((a, b) => b.score - a.score)[0];
    for (const kind of new Set(supplyFindings.map((f) => supplyKind(f.id)))) kinds[kind]++;
    for (const ref of refs) {
      const key = `${ref.manager}\u0000${ref.name}`;
      let g = packages.get(key);
      if (!g) {
        g = { key, manager: ref.manager, name: ref.name, action: ref.action, count: 0, last: r.ts_utc, lastRow: row, maxScore: 0, topFinding: null, workspaces: [], ws: new Set() };
        packages.set(key, g);
      }
      g.count++;
      if (r.ts_utc >= g.last) {
        g.last = maxIso(g.last, r.ts_utc);
        g.lastRow = row;
      }
      if (top && top.score >= g.maxScore) {
        g.maxScore = top.score;
        g.topFinding = top.id;
      }
      if (r.workspace) g.ws.add(r.workspace);
    }
    for (const f of supplyFindings) {
      let g = findings.get(f.id);
      if (!g) {
        g = { id: f.id, kind: supplyKind(f.id), category: f.category, confidence: f.confidence, count: 0, maxScore: 0, explanation: f.explanation, mitigation: f.mitigation, packages: [], pk: new Set() };
        findings.set(f.id, g);
      }
      g.count++;
      g.maxScore = Math.max(g.maxScore, f.score);
      for (const ref of refs) g.pk.add(ref.name);
    }
  }
  return {
    kinds,
    packages: [...packages.values()].map(({ ws, ...g }) => ({ ...g, workspaces: [...ws].sort() })).sort((a, b) => b.maxScore - a.maxScore || b.count - a.count),
    findings: [...findings.values()].map(({ pk, ...g }) => ({ ...g, packages: [...pk].sort() })).sort((a, b) => b.maxScore - a.maxScore),
  };
}

function kindLabel(t: Dict, g: FindingGroup): string {
  const s = t.supply;
  switch (g.kind) {
    case "typosquat": return s.kindTyposquat;
    case "registry": return s.kindRegistry;
    case "remote": return s.kindRemote;
    case "scripts": return s.kindScripts;
    case "other": return g.id;
  }
}

const KIND_ICON = { typosquat: SpellCheck, registry: Replace, remote: Zap, scripts: Download, other: PackageSearch } as const;

function FindingGroupCard({ group }: { group: FindingGroup }) {
  const t = useT();
  const s = t.supply;
  const locale = useLocale();
  const Icon = KIND_ICON[group.kind];
  return (
    <article className="rounded-lg border border-line bg-surface-2 p-4">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <Icon className="size-4.5 shrink-0 text-fg-2" aria-hidden />
        <h4 className="text-lg font-semibold text-fg">{kindLabel(t, group)}</h4>
        <RiskPill score={group.maxScore} />
        <span className="tabular ml-auto text-sm text-fg-3">{fmt(s.occurrences, { n: formatNumber(group.count, locale) })}</span>
      </header>
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <code className="text-sm text-fg-2">{group.id}</code>
        <CategoryChip category={group.category} />
        <ConfidenceBadge confidence={group.confidence} />
      </div>
      <p className="mt-2.5 text-base text-fg-2">{group.explanation}</p>
      {group.mitigation && (
        <p className="mt-2 flex gap-2 text-base text-fg-2">
          <Lightbulb className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />
          <span><span className="font-medium text-fg">{t.common.mitigation}: </span>{group.mitigation}</span>
        </p>
      )}
      {group.packages.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="text-sm text-fg-3">{s.affected}</span>
          {group.packages.slice(0, 10).map((p) => <code key={p} className="rounded-md border border-line bg-surface px-1.5 py-0.5 text-sm text-fg">{p}</code>)}
          {group.packages.length > 10 && <span className="tabular text-sm text-fg-3">+{group.packages.length - 10}</span>}
        </div>
      )}
    </article>
  );
}

function SupplyView({ rows }: { rows: EventRow[] }) {
  const t = useT();
  const s = t.supply;
  const locale = useLocale();
  const openEvent = useApp((st) => st.openEvent);
  const data = useMemo(() => summarise(rows), [rows]);

  const columns = useMemo<ColumnDef<PackageGroup>[]>(() => [
    { id: "manager", header: s.colManager, accessorFn: (g) => g.manager, cell: ({ row }) => <Badge tone="var(--series-3)">{row.original.manager}</Badge> },
    {
      id: "name", header: s.colPackage, accessorFn: (g) => g.name,
      cell: ({ row }) => (
        <span className="flex min-w-0 items-center gap-2">
          <code className="truncate text-sm font-medium text-fg" title={row.original.name}>{row.original.name}</code>
          {row.original.action === "execute" && <Badge tone="var(--warn)" icon={Zap}>{s.actionExecute}</Badge>}
        </span>
      ),
    },
    { id: "count", header: s.colRequests, accessorFn: (g) => g.count, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => formatNumber(row.original.count, locale) },
    { id: "last", header: s.colLastSeen, accessorFn: (g) => g.last, sortDescFirst: true, cell: ({ row }) => <span className="tabular text-fg-2">{formatSmartTime(row.original.last, locale)}</span> },
    { id: "projects", header: s.colProjects, accessorFn: (g) => g.workspaces.length, cell: ({ row }) => <ProjectChips workspaces={row.original.workspaces} /> },
    {
      id: "finding", header: s.colTopFinding, accessorFn: (g) => g.maxScore, sortDescFirst: true,
      cell: ({ row }) => (
        <span className="flex min-w-0 items-center gap-2">
          <RiskPill score={row.original.maxScore} />
          {row.original.topFinding ? <code className="truncate text-sm text-fg-2" title={row.original.topFinding}>{row.original.topFinding}</code> : <span className="text-fg-3">–</span>}
        </span>
      ),
    },
  ], [s, locale]);

  return (
    <>
      <KpiGrid cols={5}>
        <Kpi label={s.kpiInstalls} value={formatNumber(rows.length, locale)} hint={s.kpiInstallsHint} icon={Package} tone="var(--series-3)" />
        <Kpi label={s.kpiPackages} value={formatNumber(data.packages.length, locale)} hint={s.kpiPackagesHint} icon={PackageSearch} tone="var(--accent-2)" />
        <Kpi label={s.kpiTyposquat} value={formatNumber(data.kinds.typosquat, locale)} hint={s.kpiTyposquatHint} icon={SpellCheck} tone="var(--risk-high)" alert={data.kinds.typosquat > 0} />
        <Kpi label={s.kpiRegistry} value={formatNumber(data.kinds.registry, locale)} hint={s.kpiRegistryHint} icon={Replace} tone="var(--risk-high)" alert={data.kinds.registry > 0} />
        <Kpi label={s.kpiRemote} value={formatNumber(data.kinds.remote, locale)} hint={s.kpiRemoteHint} icon={Zap} tone="var(--warn)" />
      </KpiGrid>

      <div className="grid grid-cols-1 gap-5 2xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Card title={s.packagesTitle} subtitle={s.packagesHint} padded={false} bodyClassName="pt-2">
          <DataTable
            ariaLabel={s.tablePackages}
            data={data.packages}
            columns={columns}
            getRowId={(g) => g.key}
            onRowClick={(g) => openEvent(g.lastRow)}
            maxHeight={520}
            dense
            empty={<EmptyState icon={PackageSearch} title={s.noPackages} body={s.noPackagesBody} compact />}
          />
        </Card>
        <Card title={s.findingsTitle} subtitle={s.findingsHint}>
          {data.findings.length === 0 ? <p className="text-base text-fg-3">{t.common.noFindings}</p> : (
            <div className="max-h-[480px] space-y-3 overflow-y-auto pr-1">
              {data.findings.map((g) => <FindingGroupCard key={g.id} group={g} />)}
            </div>
          )}
        </Card>
      </div>

      <Card
        className="mt-5"
        title={s.eventsTitle}
        subtitle={s.eventsHint}
        padded={false}
        bodyClassName="pt-2"
        actions={<span className="tabular text-sm text-fg-3">{fmt(t.common.eventsCount, { n: formatNumber(rows.length, locale) })}</span>}
      >
        <EventTable ariaLabel={s.tableEvents} rows={rows} columns={CENTER_COLUMNS} height={Math.min(460, 44 + Math.max(3, rows.length) * 42)} />
      </Card>
    </>
  );
}

function OsvNote() {
  const s = useT().supply;
  const locale = useLocale();
  const osv = useApp((st) => st.status?.osv);
  if (osv?.enabled) {
    const present = (osv.ecosystems ?? []).filter((e) => e.updated);
    return (
      <Callout tone={osv.stale ? "warn" : "ok"} title={osv.stale ? s.osvStaleTitle : s.osvOnTitle} className="mt-5">
        <p className="mt-1">{s.osvOnBody}</p>
        <ul className="mt-2 list-disc space-y-0.5 pl-4.5">
          {present.map((e) => (
            <li key={e.ecosystem}>
              <span className="font-medium text-fg">{e.ecosystem}</span>{" — "}
              {fmt(s.osvEcosystemLine, { n: formatNumber(e.advisories, locale), when: formatSmartTime(e.updated ?? "", locale) })}
            </li>
          ))}
        </ul>
        <p className="mt-2 text-fg-3">{s.osvBody3}</p>
      </Callout>
    );
  }
  return (
    <Callout tone="neutral" icon={CloudOff} title={s.osvTitle} className="mt-5">
      <ul className="mt-1 list-disc space-y-1 pl-4.5">
        <li>{s.osvBody1}</li>
        <li>{s.osvBody2}</li>
        <li>{s.osvBody3}</li>
      </ul>
    </Callout>
  );
}

export default function SupplyChainPage() {
  const t = useT();
  const state = useAsync(() => backend.listEvents({ packages_only: true, limit: 1000 }).then(withoutPost), [], { refreshMs: 15000 });
  return (
    <Page>
      <PageHeader title={t.supply.title} description={t.supply.description} icon={Package} />
      <AsyncView
        state={state}
        isEmpty={(rows) => rows.length === 0}
        empty={<Card><EmptyState icon={Package} title={t.supply.emptyTitle} body={t.supply.emptyBody} /></Card>}
      >
        {(rows) => <SupplyView rows={rows} />}
      </AsyncView>
      <OsvNote />
    </Page>
  );
}
