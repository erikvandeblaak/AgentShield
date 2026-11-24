import { useMemo, type ReactNode } from "react";
import { AlertTriangle, ArrowLeftRight, Fingerprint, GitCompareArrows, Plug, Radio, ShieldCheck, Unplug } from "lucide-react";
import { CENTER_COLUMNS, KpiGrid, withoutPost } from "../components/centers/shared";
import { Chart } from "../components/Chart";
import { EventTable } from "../components/EventTable";
import { FindingList } from "../components/FindingCard";
import { Page } from "../components/Page";
import { AsyncView, Badge, Callout, Card, CodeBlock, CopyButton, EmptyState, Kpi, Mono, PageHeader, SectionTitle } from "../components/ui";
import { fmt, useLocale, useT, type Dict } from "../i18n";
import { backend } from "../lib/backend";
import { tooltipHtml } from "../lib/escape";
import { formatDateTime, formatNumber } from "../lib/format";
import { useAsync } from "../lib/hooks";
import { useChartTheme } from "../theme/echarts";
import type { EventRow, McpServerInfo } from "../lib/types";

function scopeLabel(t: Dict, scope: string): string {
  const m = t.mcp;
  return ({ user: m.scopeUser, project: m.scopeProject, local: m.scopeLocal, plugin: m.scopePlugin } as Record<string, string>)[scope] ?? scope;
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[9.5rem_minmax(0,1fr)] items-start gap-3 py-1.5">
      <dt className="text-sm text-fg-3">{label}</dt>
      <dd className="min-w-0 text-base text-fg">{children}</dd>
    </div>
  );
}

function ServerCard({ server }: { server: McpServerInfo }) {
  const t = useT();
  const m = t.mcp;
  const locale = useLocale();
  const commandLine = server.command ? [server.command, ...server.args].join(" ") : null;
  return (
    <Card className="h-full" accent={server.changed_since_last_seen ? "var(--warn)" : undefined}>
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-line bg-surface-2 text-accent-2"><Plug className="size-4.5" aria-hidden /></span>
        <h3 className="min-w-0 truncate font-mono text-xl font-semibold text-fg" title={server.name}>{server.name}</h3>
        <Badge tone="var(--accent-3)" title={m.scope}>{scopeLabel(t, server.scope)}</Badge>
        <Badge tone="var(--fg-3)" icon={Radio} title={m.transport}>{server.transport}</Badge>
        {server.changed_since_last_seen && <Badge tone="var(--warn)" icon={GitCompareArrows} title={m.changedHint}>{m.changed}</Badge>}
        <span className="tabular ml-auto text-sm text-fg-2" title={m.observedCalls}>
          <span className="text-xl font-semibold text-fg">{formatNumber(server.observed_calls, locale)}</span> {m.observedCalls.toLowerCase()}
        </span>
      </header>

      <div
        role="note"
        className="mt-4 flex gap-2.5 rounded-lg border px-3 py-2.5"
        style={{
          borderColor: `color-mix(in srgb, ${server.routed_via_agentshield ? "var(--ok)" : "var(--warn)"} 32%, var(--line))`,
          background: `color-mix(in srgb, ${server.routed_via_agentshield ? "var(--ok)" : "var(--warn)"} 7%, var(--surface))`,
        }}
      >
        {server.routed_via_agentshield
          ? <ShieldCheck className="mt-0.5 size-4.5 shrink-0 text-ok" aria-hidden />
          : <Unplug className="mt-0.5 size-4.5 shrink-0 text-warn" aria-hidden />}
        <div className="min-w-0">
          <div className="text-base font-semibold text-fg">{server.routed_via_agentshield ? m.routed : m.direct}</div>
          <p className="mt-0.5 text-sm text-fg-2">{server.routed_via_agentshield ? m.routedBody : m.directBody}</p>
        </div>
      </div>

      {server.changed_since_last_seen && (
        <p className="mt-2.5 flex gap-2 text-sm text-fg-2"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />{m.changedHint}</p>
      )}

      <dl className="mt-3">
        {commandLine && <Row label={m.commandLabel}><CodeBlock text={commandLine} maxHeight={96} /></Row>}
        {server.url_host && <Row label={m.hostLabel}><Mono text={server.url_host} /></Row>}
        <Row label={m.source}><Mono text={server.source} className="text-fg-2" /></Row>
        <Row label={m.envKeys}>
          {server.env_keys.length === 0 ? <span className="text-fg-3">{m.noEnv}</span> : (
            <div>
              <div className="flex flex-wrap gap-1.5">
                {server.env_keys.map((k) => <code key={k} className="rounded-md border border-line bg-surface-2 px-1.5 py-0.5 text-sm text-fg">{k}</code>)}
              </div>
              <div className="mt-1 text-sm text-fg-3">{m.envNote}</div>
            </div>
          )}
        </Row>
        <Row label={m.fingerprint}>
          <span className="inline-flex items-center gap-1.5">
            <Fingerprint className="size-4 text-fg-3" aria-hidden />
            <code className="text-sm text-fg-2">{server.fingerprint}</code>
            <CopyButton text={server.fingerprint} />
          </span>
        </Row>
        <Row label={m.firstSeen}><span className="tabular text-fg-2">{formatDateTime(server.first_seen, locale)}</span></Row>
        <Row label={m.toolsSeen}>
          {server.tools_seen.length === 0 ? <span className="text-fg-3">{m.noToolsSeen}</span> : (
            <div className="flex flex-wrap gap-1.5">
              {server.tools_seen.map((tool) => <code key={tool} className="rounded-md border border-line bg-surface-2 px-1.5 py-0.5 text-sm text-fg-2">{tool}</code>)}
            </div>
          )}
        </Row>
      </dl>

      <div className="mt-3 border-t border-line pt-3">
        <div className="eyebrow mb-2">{m.findings} · {server.findings.length}</div>
        {server.findings.length === 0 ? <p className="text-base text-fg-3">{m.noFindings}</p> : <FindingList findings={server.findings} />}
      </div>
    </Card>
  );
}

const MAX_BARS = 12;

function CallsChart({ rows }: { rows: EventRow[] }) {
  const t = useT();
  const th = useChartTheme();
  const data = useMemo(() => {
    const counts = new Map<string, number>();
    for (const { record: r } of rows) {
      if (r.action.type !== "mcp_call") continue;
      const key = `${r.action.server} › ${r.action.tool}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [rows]);
  const top = data.slice(0, MAX_BARS);
  const option = useMemo(() => ({
    grid: { ...th.grid4, left: 4, right: 36, top: 4 },
    tooltip: {
      ...th.tooltip,
      trigger: "axis",
      axisPointer: { type: "shadow", shadowStyle: { color: th.name === "dark" ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.04)" } },
      formatter: (p: unknown) => {
        const first = (Array.isArray(p) ? p[0] : p) as { name?: string; value?: number } | undefined;
        return tooltipHtml(String(first?.name ?? ""), [{ color: th.series[0], label: t.mcp.calls, value: first?.value ?? 0 }]);
      },
    },
    xAxis: { type: "value", ...th.valueAxis },
    yAxis: {
      type: "category", inverse: true, data: top.map(([k]) => k), ...th.categoryAxis,
      axisLabel: { color: th.fg2, fontFamily: th.fontMono, fontSize: 12, width: 220, overflow: "truncate" },
    },
    series: [{
      type: "bar", data: top.map(([, n]) => n), barMaxWidth: 16,
      itemStyle: { color: th.series[0], borderRadius: [0, 4, 4, 0] },
      label: { show: true, position: "right", color: th.fg2, fontFamily: th.fontSans, fontSize: 12 },
    }],
  }), [th, top, t]);
  if (top.length === 0) return <EmptyState icon={ArrowLeftRight} title={t.mcp.noEventsTitle} compact />;
  return (
    <>
      <Chart option={option} height={Math.max(140, top.length * 30 + 36)} ariaLabel={t.mcp.chartAria} />
      {data.length > MAX_BARS && <p className="mt-1 text-sm text-fg-3">{fmt(t.mcp.moreTools, { n: MAX_BARS })}</p>}
    </>
  );
}

export default function McpPage() {
  const t = useT();
  const m = t.mcp;
  const locale = useLocale();
  const servers = useAsync(() => backend.mcpServers(), [], { refreshMs: 30000 });
  const events = useAsync(() => backend.listEvents({ mcp_only: true, limit: 500 }).then(withoutPost), [], { refreshMs: 15000 });

  const list = servers.data ?? [];
  const totalCalls = list.reduce((n, s) => n + s.observed_calls, 0);
  const unknown = useMemo(() => {
    const known = new Set((servers.data ?? []).map((s) => s.name));
    const names = new Set<string>();
    let n = 0;
    for (const { record: r } of events.data ?? []) {
      if (r.action.type === "mcp_call" && !known.has(r.action.server)) {
        names.add(r.action.server);
        n++;
      }
    }
    return { n, names: [...names] };
  }, [servers.data, events.data]);

  return (
    <Page>
      <PageHeader title={m.title} description={m.description} icon={Plug} />
      <AsyncView state={servers}>
        {(data) => (
          <>
            <KpiGrid cols={5}>
              <Kpi label={m.kpiServers} value={formatNumber(data.length, locale)} hint={m.kpiServersHint} icon={Plug} tone="var(--accent-2)" />
              <Kpi
                label={m.kpiDirect}
                value={formatNumber(data.filter((s) => !s.routed_via_agentshield).length, locale)}
                hint={m.kpiDirectHint}
                icon={Unplug}
                tone="var(--warn)"
              />
              <Kpi
                label={m.kpiChanged}
                value={formatNumber(data.filter((s) => s.changed_since_last_seen).length, locale)}
                hint={m.kpiChangedHint}
                icon={GitCompareArrows}
                tone="var(--warn)"
                alert={data.some((s) => s.changed_since_last_seen)}
              />
              <Kpi label={m.kpiCalls} value={formatNumber(totalCalls, locale)} hint={m.kpiCallsHint} icon={ArrowLeftRight} tone="var(--info)" />
              <Kpi label={m.kpiFindings} value={formatNumber(data.reduce((n, s) => n + s.findings.length, 0), locale)} hint={m.kpiFindingsHint} icon={AlertTriangle} tone="var(--risk-high)" />
            </KpiGrid>

            <SectionTitle hint={m.serversHint}>{m.servers}</SectionTitle>
            {data.length === 0 ? (
              <Card><EmptyState icon={Plug} title={m.noServersTitle} body={m.noServersBody} /></Card>
            ) : (
              <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                {data.map((s) => <ServerCard key={`${s.scope}:${s.source}:${s.name}`} server={s} />)}
              </div>
            )}
          </>
        )}
      </AsyncView>

      <div className="mt-6 grid grid-cols-1 gap-5 2xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Card title={m.chartTitle} subtitle={m.chartHint}>
          <AsyncView state={events}>{(rows) => <CallsChart rows={rows} />}</AsyncView>
        </Card>
        <Card title={m.eventsTitle} subtitle={m.eventsHint} padded={false} bodyClassName="pt-2">
          <AsyncView state={events}>
            {(rows) => (
              <EventTable
                ariaLabel={m.tableEvents}
                rows={rows}
                columns={CENTER_COLUMNS}
                height={420}
                empty={<EmptyState icon={ArrowLeftRight} title={m.noEventsTitle} body={m.noEventsBody} compact />}
              />
            )}
          </AsyncView>
        </Card>
      </div>

      {unknown.n > 0 && (
        <Callout tone="warn" className="mt-5">{fmt(m.unknownServerNote, { n: unknown.n, names: unknown.names.join(", ") })}</Callout>
      )}
    </Page>
  );
}
