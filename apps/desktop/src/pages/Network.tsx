import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { ArrowRight, Ban, CircleHelp, Globe, Radar, Search, Send, ShieldOff, Waypoints } from "lucide-react";
import { RiskPill } from "../components/badges";
import { CENTER_COLUMNS_PHASE, KpiGrid, ProjectChips, maxIso } from "../components/centers/shared";
import { Chart } from "../components/Chart";
import { DataTable } from "../components/DataTable";
import { EventTable } from "../components/EventTable";
import { Page } from "../components/Page";
import { AsyncView, Callout, Card, EmptyState, Kpi, Mono, PageHeader, Segmented } from "../components/ui";
import { fmt, useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { tooltipHtml } from "../lib/escape";
import { basename, formatNumber, formatSmartTime, hostsOfRecord, levelForScore } from "../lib/format";
import { useAsync } from "../lib/hooks";
import { useApp } from "../store/app";
import { useChartTheme } from "../theme/echarts";
import type { EventRow } from "../lib/types";

interface Destination {
  host: string;
  intended: number;
  observed: number;
  failed: number;
  blocked: number;
  maxScore: number;
  last: string;
  lastRow: EventRow;
  workspaces: string[];
  agents: Record<string, number>;
}

interface Summary {
  destinations: Destination[];
  intended: number;
  observed: number;
  failed: number;
  blocked: number;
  unresolved: number;
  searches: EventRow[];
}

function isStopped(row: EventRow): boolean {
  return row.record.actual_decision === "deny" || row.record.outcome === "blocked" || row.observed_outcome === "blocked";
}

/** Built ONLY from hosts written in recorded tool calls (hostsOfRecord). Nothing is inferred. */
function summarise(rows: EventRow[]): Summary {
  const map = new Map<string, Destination & { ws: Set<string> }>();
  const searches: EventRow[] = [];
  let intended = 0, observed = 0, failed = 0, blocked = 0, unresolved = 0;
  for (const row of rows) {
    const r = row.record;
    if (r.action.type === "web_search") {
      if (r.phase === "pre") searches.push(row);
      continue;
    }
    const hosts = hostsOfRecord(r);
    if (hosts.length === 0 || r.phase === "lifecycle") continue;
    const stopped = r.phase === "pre" && isStopped(row);
    if (r.phase === "pre") {
      intended++;
      if (stopped) blocked++;
      else if (row.observed_outcome == null) unresolved++;
    } else if (r.outcome === "executed") observed++;
    else if (r.outcome === "failed") failed++;
    for (const host of hosts) {
      let d = map.get(host);
      if (!d) {
        d = { host, intended: 0, observed: 0, failed: 0, blocked: 0, maxScore: 0, last: r.ts_utc, lastRow: row, workspaces: [], agents: {}, ws: new Set() };
        map.set(host, d);
      }
      if (r.phase === "pre") {
        d.intended++;
        d.agents[r.agent] = (d.agents[r.agent] ?? 0) + 1;
        if (stopped) d.blocked++;
      } else if (r.outcome === "executed") d.observed++;
      else if (r.outcome === "failed") d.failed++;
      d.maxScore = Math.max(d.maxScore, r.risk.score);
      if (r.ts_utc >= d.last) {
        d.last = maxIso(d.last, r.ts_utc);
        if (r.phase === "pre" || d.lastRow.record.phase !== "pre") d.lastRow = row;
      }
      if (r.workspace) d.ws.add(r.workspace);
    }
  }
  const destinations = [...map.values()]
    .map(({ ws, ...d }) => ({ ...d, workspaces: [...ws].sort() }))
    .sort((a, b) => b.maxScore - a.maxScore || b.intended - a.intended);
  return { destinations, intended, observed, failed, blocked, unresolved, searches };
}

const MAX_GRAPH_HOSTS = 14;

interface GraphDatum { kind: "agent" | "host"; label: string; intended: number; observed?: number; blocked?: number; score?: number }

function DestinationGraph({ destinations }: { destinations: Destination[] }) {
  const t = useT();
  const n = t.network;
  const th = useChartTheme();
  const hosts = useMemo(() => [...destinations].sort((a, b) => b.maxScore - a.maxScore || b.intended - a.intended).slice(0, MAX_GRAPH_HOSTS), [destinations]);
  const height = Math.max(300, hosts.length * 30 + 40);

  const option = useMemo(() => {
    const agents = new Map<string, number>();
    for (const d of hosts) for (const [a, c] of Object.entries(d.agents)) agents.set(a, (agents.get(a) ?? 0) + c);
    const agentNames = [...agents.keys()].sort();
    const maxCount = Math.max(1, ...hosts.map((d) => d.intended));
    const H = 100;
    const nodes = [
      ...agentNames.map((a, i) => ({
        id: `agent:${a}`, name: a, x: 0, y: ((i + 1) / (agentNames.length + 1)) * H, symbol: "roundRect", symbolSize: 30,
        itemStyle: { color: th.accent2, borderColor: th.surface, borderWidth: 2 },
        label: { show: true, position: "left", distance: 8, color: th.fg, fontFamily: th.fontSans, fontSize: 13, fontWeight: 600 },
        datum: { kind: "agent", label: a, intended: agents.get(a) ?? 0 } satisfies GraphDatum,
      })),
      ...hosts.map((d, i) => ({
        id: `host:${d.host}`, name: d.host, x: 60, y: hosts.length === 1 ? H / 2 : (i / (hosts.length - 1)) * H,
        symbol: "circle", symbolSize: 12 + Math.round((d.intended / maxCount) * 12),
        itemStyle: { color: th.level[levelForScore(d.maxScore)], borderColor: th.surface, borderWidth: 2 },
        label: { show: true, position: "right", distance: 8, color: th.fg2, fontFamily: th.fontMono, fontSize: 12, width: 250, overflow: "truncate" },
        datum: { kind: "host", label: d.host, intended: d.intended, observed: d.observed, blocked: d.blocked, score: d.maxScore } satisfies GraphDatum,
      })),
    ];
    const links = hosts.flatMap((d) => Object.entries(d.agents).map(([a, c]) => ({
      source: `agent:${a}`, target: `host:${d.host}`, value: c,
      lineStyle: { width: 1 + (c / maxCount) * 5, color: th.level[levelForScore(d.maxScore)], opacity: 0.45, curveness: 0.12 },
      datum: { kind: "host", label: `${a} → ${d.host}`, intended: c } satisfies GraphDatum,
    })));
    return {
      tooltip: {
        ...th.tooltip,
        trigger: "item",
        formatter: (p: unknown) => {
          const d = (p as { data?: { datum?: GraphDatum } }).data?.datum;
          if (!d) return "";
          const rows = [{ label: n.colIntended, value: d.intended }];
          if (d.observed != null) rows.push({ label: n.colObserved, value: d.observed });
          if (d.blocked != null) rows.push({ label: n.colBlocked, value: d.blocked });
          if (d.score != null) rows.push({ label: n.colMaxScore, value: d.score });
          return tooltipHtml(d.label, rows, d.kind === "agent" ? n.nodeAgent : undefined);
        },
      },
      series: [{
        type: "graph", layout: "none", roam: false, left: 150, right: 280, top: 20, bottom: 20,
        edgeSymbol: ["none", "arrow"], edgeSymbolSize: 7,
        emphasis: { focus: "adjacency", lineStyle: { opacity: 0.9 } },
        data: nodes, links,
      }],
    };
  }, [hosts, th, n]);

  if (hosts.length === 0) return <EmptyState icon={Waypoints} title={t.common.noData} compact />;
  return (
    <>
      <Chart option={option} height={height} ariaLabel={n.graphAria} />
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-fg-3">
        {(["informational", "low", "medium", "high", "critical"] as const).map((l) => (
          <span key={l} className="flex items-center gap-1.5"><span className="size-2.5 rounded-full" style={{ background: th.level[l] }} aria-hidden />{t.enums.level[l]}</span>
        ))}
        {destinations.length > hosts.length && <span className="ml-auto">{fmt(n.graphTop, { n: hosts.length, total: destinations.length })}</span>}
      </div>
    </>
  );
}

type PhaseFilter = "all" | "pre" | "post";

function NetworkView({ rows }: { rows: EventRow[] }) {
  const t = useT();
  const n = t.network;
  const locale = useLocale();
  const openEvent = useApp((s) => s.openEvent);
  const [phase, setPhase] = useState<PhaseFilter>("all");
  const data = useMemo(() => summarise(rows), [rows]);
  const shown = useMemo(() => (phase === "all" ? rows : rows.filter((r) => r.record.phase === phase)), [rows, phase]);
  const num = (x: number) => formatNumber(x, locale);

  const destColumns = useMemo<ColumnDef<Destination>[]>(() => [
    { id: "host", header: n.colHost, accessorFn: (d) => d.host, cell: ({ row }) => <Mono text={row.original.host} className="max-w-80 font-medium" /> },
    { id: "intended", header: n.colIntended, accessorFn: (d) => d.intended, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => num(row.original.intended) },
    { id: "observed", header: n.colObserved, accessorFn: (d) => d.observed, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => num(row.original.observed) },
    {
      id: "blocked", header: n.colBlocked, accessorFn: (d) => d.blocked, sortDescFirst: true, meta: { align: "right" },
      cell: ({ row }) => (row.original.blocked > 0 ? <span className="font-semibold text-danger">{num(row.original.blocked)}</span> : <span className="text-fg-3">0</span>),
    },
    { id: "max", header: n.colMaxScore, accessorFn: (d) => d.maxScore, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => <RiskPill score={row.original.maxScore} /> },
    { id: "last", header: n.colLastSeen, accessorFn: (d) => d.last, sortDescFirst: true, cell: ({ row }) => <span className="tabular text-fg-2">{formatSmartTime(row.original.last, locale)}</span> },
    { id: "projects", header: n.colProjects, accessorFn: (d) => d.workspaces.length, cell: ({ row }) => <ProjectChips workspaces={row.original.workspaces} /> },
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [n, locale]);

  const searchColumns = useMemo<ColumnDef<EventRow>[]>(() => [
    { id: "time", header: t.common.time, accessorFn: (r) => r.record.ts_utc, meta: { className: "w-28" }, cell: ({ row }) => <span className="tabular text-fg-2">{formatSmartTime(row.original.record.ts_utc, locale)}</span> },
    {
      id: "query", header: n.colQuery, accessorFn: (r) => (r.record.action.type === "web_search" ? r.record.action.query : r.record.summary), enableSorting: false,
      cell: ({ row }) => {
        const a = row.original.record.action;
        return <Mono text={a.type === "web_search" ? a.query : row.original.record.summary} className="max-w-96" />;
      },
    },
    { id: "project", header: t.common.project, accessorFn: (r) => basename(r.record.workspace), cell: ({ row }) => <span className="text-fg-2">{basename(row.original.record.workspace) || "–"}</span> },
    { id: "risk", header: t.common.risk, accessorFn: (r) => r.record.risk.score, sortDescFirst: true, meta: { align: "right" }, cell: ({ row }) => <RiskPill score={row.original.record.risk.score} /> },
  ], [t, n, locale]);

  return (
    <>
      <KpiGrid cols={5}>
        <Kpi label={n.kpiIntended} value={num(data.intended)} hint={n.kpiIntendedHint} icon={Send} tone="var(--accent-2)" />
        <Kpi label={n.kpiObserved} value={num(data.observed)} hint={n.kpiObservedHint} icon={Radar} tone="var(--accent-3)" />
        <Kpi label={n.kpiBlocked} value={num(data.blocked)} hint={n.kpiBlockedHint} icon={Ban} tone="var(--danger)" />
        <Kpi label={n.kpiHosts} value={num(data.destinations.length)} hint={n.kpiHostsHint} icon={Globe} tone="var(--info)" />
        <Kpi label={n.kpiSearches} value={num(data.searches.length)} hint={n.kpiSearchesHint} icon={Search} />
      </KpiGrid>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Card title={n.graphTitle} subtitle={n.graphHint}>
          <DestinationGraph destinations={data.destinations} />
        </Card>
        <Card title={n.phaseTitle} subtitle={n.phaseHint}>
          <div className="space-y-3">
            <div className="rounded-lg border border-accent-2/40 bg-accent-2/5 p-4">
              <div className="flex items-baseline justify-between gap-3">
                <h4 className="text-base font-semibold text-fg">{n.intendedTitle}</h4>
                <span className="tabular text-2xl font-semibold text-fg">{num(data.intended)}</span>
              </div>
              <p className="mt-1 text-sm text-fg-2">{n.intendedBody}</p>
            </div>
            <div className="flex justify-center text-fg-3"><ArrowRight className="size-4 rotate-90" aria-hidden /></div>
            <div className="rounded-lg border border-accent-3/40 bg-accent-3/5 p-4">
              <div className="flex items-baseline justify-between gap-3">
                <h4 className="text-base font-semibold text-fg">{n.observedTitle}</h4>
                <span className="tabular text-2xl font-semibold text-fg">{num(data.observed)}</span>
              </div>
              <p className="mt-1 text-sm text-fg-2">{n.observedBody}</p>
              {data.failed > 0 && <p className="mt-1.5 text-sm text-warn">{fmt(n.reportedFailed, { n: num(data.failed) })}</p>}
            </div>
            {data.unresolved > 0 && (
              <p className="flex gap-2 text-sm text-fg-3">
                <CircleHelp className="mt-0.5 size-4 shrink-0" aria-hidden />
                <span><span className="font-medium text-fg-2">{n.noPost}. </span>{fmt(n.noPostBody, { n: num(data.unresolved) })}</span>
              </p>
            )}
          </div>
        </Card>
      </div>

      <Card className="mt-5" title={n.destinationsTitle} subtitle={n.destinationsHint} padded={false} bodyClassName="pt-2">
        <DataTable
          ariaLabel={n.tableDestinations}
          data={data.destinations}
          columns={destColumns}
          getRowId={(d) => d.host}
          onRowClick={(d) => openEvent(d.lastRow)}
          maxHeight={380}
          dense
        />
      </Card>

      <div className="mt-5 grid grid-cols-1 gap-5 2xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Card
          title={n.eventsTitle}
          subtitle={n.eventsHint}
          padded={false}
          bodyClassName="pt-2"
          actions={
            <Segmented
              size="sm"
              label={n.phaseFilter}
              value={phase}
              onChange={setPhase}
              options={[{ value: "all", label: n.phaseAll }, { value: "pre", label: n.phasePre }, { value: "post", label: n.phasePost }]}
            />
          }
        >
          <EventTable ariaLabel={n.tableEvents} rows={shown} columns={CENTER_COLUMNS_PHASE} height={420} />
        </Card>
        <Card title={n.searchesTitle} subtitle={n.searchesHint} padded={false} bodyClassName="pt-2">
          <DataTable
            ariaLabel={n.tableSearches}
            data={data.searches}
            columns={searchColumns}
            getRowId={(r) => String(r.record.id)}
            onRowClick={openEvent}
            maxHeight={420}
            dense
            empty={<EmptyState icon={Search} title={n.noSearches} compact />}
          />
        </Card>
      </div>
    </>
  );
}

function Limitations() {
  const n = useT().network;
  return (
    <Callout tone="warn" icon={ShieldOff} title={n.limitationsTitle} className="mt-5">
      <ul className="mt-1 list-disc space-y-1 pl-4.5">
        {[n.limitation1, n.limitation2, n.limitation3, n.limitation4, n.limitation5].map((l) => <li key={l}>{l}</li>)}
      </ul>
    </Callout>
  );
}

export default function NetworkPage() {
  const t = useT();
  const state = useAsync(() => backend.listEvents({ network_only: true, limit: 1000 }), [], { refreshMs: 15000 });
  return (
    <Page>
      <PageHeader title={t.network.title} description={t.network.description} icon={Globe} />
      <AsyncView
        state={state}
        isEmpty={(rows) => rows.length === 0}
        empty={<Card><EmptyState icon={Globe} title={t.network.emptyTitle} body={t.network.emptyBody} /></Card>}
      >
        {(rows) => <NetworkView rows={rows} />}
      </AsyncView>
      <Limitations />
    </Page>
  );
}
