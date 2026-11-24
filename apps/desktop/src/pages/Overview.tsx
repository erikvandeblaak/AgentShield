import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import {
  Activity, Ban, Bot, ChevronRight, CircleAlert, Gauge, Hand, HeartPulse, Layers, Radio, ShieldQuestion, Timer, TriangleAlert, Unplug, Users,
  type LucideIcon,
} from "lucide-react";
import { ActualBadge, DecisionBadge, MODE_ICON, RiskPill } from "../components/badges";
import { ActivityHeatmap, PerHourChart, PerMinuteChart } from "../components/overview/charts";
import { Page } from "../components/Page";
import { AsyncView, Button, Card, EmptyState, Kpi, PageHeader, Segmented, Skeleton, cx } from "../components/ui";
import { fmt, useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { ModeChangeDialog } from "../layout/ModeSwitcher";
import { basename, errorMessage, formatCompact, formatDateTime, formatDuration, formatLatency, formatNumber, formatSmartTime } from "../lib/format";
import { useAsync, useLiveEvents } from "../lib/hooks";
import { navigate } from "../lib/router";
import { useApp } from "../store/app";
import { CATEGORY_FAMILY, FAMILY_VAR, LEVELS, LEVEL_VAR, MODE_VAR, v } from "../theme/palette";
import type { CountItem, LatencySummary, Mode, RiskCategory, RiskLevel, Stats } from "../lib/types";

const MODE_ORDER: Mode[] = ["monitor", "shadow", "interactive", "enforce", "lockdown"];

type WindowId = "1" | "24" | "168" | "720";

function HealthRow({ icon: Icon, label, value, tone, action }: { icon: LucideIcon; label: string; value: ReactNode; tone: string; action?: ReactNode }) {
  return (
    <li className="flex items-center gap-3 py-2">
      <span className="tone flex size-8 shrink-0 items-center justify-center rounded-lg" style={{ "--tone": tone } as CSSProperties}>
        <Icon className="size-4" aria-hidden />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-sm text-fg-3">{label}</div>
        <div className="truncate text-base font-medium text-fg">{value}</div>
      </div>
      {action}
    </li>
  );
}

function ModeHero() {
  const t = useT();
  const o = t.overview;
  const status = useApp((s) => s.status);
  const connection = useApp((s) => s.connection);
  const demo = useApp((s) => s.demo);
  const agents = useAsync(() => backend.agents(), [], { refreshMs: 30_000 });
  const [target, setTarget] = useState<Mode | null>(null);
  if (!status) return null;
  const pick = (next: Mode) => {
    if (next === status.mode) return;
    if (next === "monitor" || next === "shadow") {
      useApp.getState().setMode(next).catch((e: unknown) => useApp.getState().toast("danger", `${t.shell.modeDialog.failed}: ${errorMessage(e)}`));
    } else setTarget(next);
  };
  const mode = status.mode;
  const m = t.enums.mode[mode];
  const Icon = MODE_ICON[mode];
  const tone = v(MODE_VAR[mode]);
  const cc = agents.data?.find((a) => a.id === "claude-code");
  const integ = cc?.integration;
  const integTone = !cc?.detected || !integ?.installed ? "var(--warn)" : integ.verified && integ.problems.length === 0 ? "var(--ok)" : "var(--warn)";
  const integText = !cc ? (agents.loading ? t.common.loading : o.integrationNotDetected)
    : !cc.detected ? o.integrationNotDetected
    : !integ?.installed ? o.integrationMissing
    : integ.verified && integ.problems.length === 0 ? o.integrationVerified
    : fmt(o.integrationProblems, { n: Math.max(1, integ.problems.length + integ.missing_events.length) });
  const feedOk = demo || connection === "connected" || connection === "unknown";
  return (
    <div className="grid gap-5 xl:grid-cols-3">
      <section
        aria-label={`${m.banner} — ${m.tagline}`}
        className="relative overflow-hidden rounded-xl border bg-surface shadow-card xl:col-span-2"
        style={{ "--tone": tone, borderColor: "color-mix(in srgb, var(--tone) 38%, var(--line))", background: "linear-gradient(110deg, color-mix(in srgb, var(--tone) 13%, var(--surface)) 0%, var(--surface) 62%)" } as CSSProperties}
      >
        <Icon aria-hidden className="pointer-events-none absolute -right-6 -bottom-10 size-56 text-(--tone) opacity-[0.07]" strokeWidth={1.25} />
        <div className="relative flex h-full flex-col justify-between gap-5 p-6">
          <div className="flex items-start gap-4">
            <span className="tone flex size-14 shrink-0 items-center justify-center rounded-2xl"><Icon className="size-7" aria-hidden /></span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline gap-x-3">
                <h2 className="text-2xl font-bold tracking-wider text-(--tone)">{m.banner}</h2>
                <span className="text-xl font-medium text-fg">{m.tagline}</span>
              </div>
              <p className="mt-1.5 max-w-2xl text-base text-fg-2">{m.description}</p>
            </div>
          </div>
          <div>
            <div className="eyebrow mb-2">{o.changeMode}</div>
            <ol className="flex flex-wrap items-center gap-1.5">
              {MODE_ORDER.map((mm, i) => {
                const MIcon = MODE_ICON[mm];
                const on = mm === mode;
                return (
                  <li key={mm} className="flex items-center gap-1.5">
                    {i > 0 && <ChevronRight className="size-4 text-fg-3" aria-hidden />}
                    <button
                      type="button"
                      aria-pressed={on}
                      title={t.enums.mode[mm].description}
                      onClick={() => pick(mm)}
                      style={{ "--tone": v(MODE_VAR[mm]) } as CSSProperties}
                      className={cx(
                        "flex h-9 items-center gap-2 rounded-lg border px-3 text-sm font-medium transition-colors",
                        on ? "tone font-semibold" : "border-line bg-surface/60 text-fg-2 hover:border-(--tone)/60 hover:text-fg",
                      )}
                    >
                      <MIcon className={cx("size-4", !on && "text-(--tone)")} aria-hidden />
                      {t.enums.mode[mm].label}
                    </button>
                  </li>
                );
              })}
            </ol>
          </div>
          <div className="flex flex-wrap items-center gap-x-8 gap-y-2">
            <div>
              <div className="eyebrow">{o.activePolicy}</div>
              <div className="mt-0.5 font-mono text-base text-fg">{status.policy_name} <span className="text-fg-3">· {status.policy_version}</span></div>
            </div>
            {status.policy_warnings.length > 0 && (
              <div className="flex items-center gap-2 text-sm text-warn" title={status.policy_warnings.join("\n")}>
                <TriangleAlert className="size-4" aria-hidden />{status.policy_warnings[0]}
              </div>
            )}
            <div className="ml-auto flex gap-2">
              <Button size="sm" onClick={() => navigate("policy")}>{t.shell.nav.policy}</Button>
              <Button size="sm" onClick={() => navigate("simulator")}>{t.shell.nav.simulator}</Button>
            </div>
          </div>
        </div>
      </section>
      <ModeChangeDialog target={target} onClose={() => setTarget(null)} />
      <Card title={o.health} bodyClassName="pt-1! pb-3!">
        <ul className="divide-y divide-line">
          <HealthRow icon={HeartPulse} tone="var(--ok)" label={o.healthDaemon}
            value={<>{fmt(o.healthDaemonOk, { uptime: status.uptime_s != null ? formatDuration(status.uptime_s) : "–" })}{status.daemon_version ? <span className="font-normal text-fg-3"> · v{status.daemon_version}</span> : null}</>} />
          <HealthRow icon={Bot} tone={integTone} label={o.healthIntegration}
            value={<>{integText}{integ?.installed && integ.fail_closed ? <span className="font-normal text-fg-3"> · {o.integrationFailClosed}</span> : null}</>}
            action={<Button size="sm" variant="ghost" onClick={() => navigate("agents")}>{o.manage}</Button>} />
          <HealthRow icon={status.degraded ? CircleAlert : Layers} tone={status.degraded ? "var(--warn)" : "var(--ok)"} label={o.healthCoverage}
            value={status.degraded ? <span title={status.degraded_reasons.join("\n")}>{o.coverageDegraded}: {status.degraded_reasons[0] ?? ""}</span> : o.coverageOk} />
          <HealthRow icon={feedOk ? Radio : Unplug} tone={feedOk ? "var(--ok)" : "var(--danger)"} label={o.healthFeed}
            value={feedOk ? t.shell.topbar.liveConnected : connection === "lagged" ? t.shell.topbar.liveLagged : t.shell.topbar.liveDisconnected} />
        </ul>
      </Card>
    </div>
  );
}

function BarList({ items, total, color, label, format, onClick }: {
  items: CountItem[];
  total?: number;
  color: (key: string) => string;
  label: (key: string) => { text: string; title?: string; mono?: boolean };
  format: (n: number) => string;
  onClick?: (key: string) => void;
}) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <ul className="space-y-3">
      {items.map((it) => {
        const l = label(it.key);
        const inner = (
          <>
            <div className="flex items-baseline justify-between gap-3">
              <span className={cx("truncate text-base text-fg", l.mono && "font-mono text-sm")} title={l.title ?? l.text}>{l.text}</span>
              <span className="tabular shrink-0 text-base font-medium text-fg">
                {format(it.count)}
                {total ? <span className="ml-1.5 text-sm font-normal text-fg-3">{Math.round((it.count / total) * 100)}%</span> : null}
              </span>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-3">
              <div className="h-full rounded-full" style={{ width: `${Math.max(2, (it.count / max) * 100)}%`, background: color(it.key) }} />
            </div>
          </>
        );
        return (
          <li key={it.key}>
            {onClick ? <button type="button" className="block w-full rounded-md text-left hover:opacity-90" onClick={() => onClick(it.key)}>{inner}</button> : inner}
          </li>
        );
      })}
    </ul>
  );
}

function RiskDistribution({ stats }: { stats: Stats }) {
  const t = useT();
  const locale = useLocale();
  const counts = new Map(stats.by_level.map((c) => [c.key, c.count]));
  const total = LEVELS.reduce((n, l) => n + (counts.get(l) ?? 0), 0);
  if (total === 0) return <EmptyState title={t.common.noData} compact />;
  const ordered: RiskLevel[] = [...LEVELS].reverse();
  return (
    <div>
      <div className="flex h-3 gap-0.5 overflow-hidden rounded-full" role="img" aria-label={t.overview.distributionSubtitle}>
        {LEVELS.map((l) => {
          const c = counts.get(l) ?? 0;
          return c > 0 ? <div key={l} style={{ flexGrow: c, background: v(LEVEL_VAR[l]), minWidth: 4 }} title={`${t.enums.level[l]}: ${c}`} /> : null;
        })}
      </div>
      <ul className="mt-4 space-y-1">
        {ordered.map((l) => {
          const c = counts.get(l) ?? 0;
          const pct = (c / total) * 100;
          return (
            <li key={l}>
              <button type="button" onClick={() => navigate("live", { min: String(l === "critical" ? 80 : l === "high" ? 60 : l === "medium" ? 40 : l === "low" ? 20 : 0) })}
                className="flex w-full items-center gap-3 rounded-md px-1.5 py-1.5 text-left hover:bg-surface-2">
                <span className="size-2.5 shrink-0 rounded-sm" style={{ background: v(LEVEL_VAR[l]) }} aria-hidden />
                <span className="flex-1 text-base text-fg">{t.enums.level[l]}</span>
                <span className="tabular text-base font-medium text-fg">{formatNumber(c, locale)}</span>
                <span className="tabular w-14 text-right text-sm text-fg-3">{pct > 0 && pct < 0.1 ? "<0.1" : pct.toFixed(1)}%</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function LatencyBlock({ title, l }: { title: string; l: LatencySummary }) {
  const t = useT();
  const locale = useLocale();
  if (l.count === 0) return <p className="text-base text-fg-3">{t.overview.latencyNone}</p>;
  const scale = Math.max(l.p99_us, 1);
  const rows: [string, number, string][] = [["p50", l.p50_us, "var(--ok)"], ["p95", l.p95_us, "var(--accent-2)"], ["p99", l.p99_us, "var(--warn)"]];
  return (
    <div>
      <div className="mb-2 flex items-baseline justify-between gap-3">
        <span className="text-sm font-medium text-fg-2">{title}</span>
        <span className="text-sm text-fg-3">{fmt(t.overview.latencySamples, { n: formatCompact(l.count, locale) })} · {fmt(t.overview.latencyMax, { value: formatLatency(l.max_us) })}</span>
      </div>
      <dl className="space-y-2">
        {rows.map(([name, us, color]) => (
          <div key={name} className="grid grid-cols-[2.25rem_1fr_5rem] items-center gap-3">
            <dt className="font-mono text-sm text-fg-3">{name}</dt>
            <dd className="h-1.5 overflow-hidden rounded-full bg-surface-3"><div className="h-full rounded-full" style={{ width: `${Math.max(2, (us / scale) * 100)}%`, background: color }} /></dd>
            <dd className="tabular text-right text-base font-medium text-fg">{formatLatency(us)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function SecurityTimeline() {
  const t = useT();
  const locale = useLocale();
  const openEvent = useApp((s) => s.openEvent);
  const rows = useAsync(() => backend.listEvents({ min_score: 60, phase: "pre", limit: 7 }), [], { refreshMs: 15_000 });
  return (
    <AsyncView state={rows} isEmpty={(d) => d.length === 0} empty={<EmptyState icon={ShieldQuestion} title={t.overview.timelineEmpty} body={t.overview.timelineEmptyBody} compact />}
      skeleton={<div className="space-y-2">{Array.from({ length: 5 }, (_, i) => <Skeleton key={i} className="h-11" />)}</div>}>
      {(data) => (
        <ol className="relative">
          <span aria-hidden className="absolute top-3 bottom-3 left-[6.5rem] w-px bg-line" />
          {data.map((row) => {
            const r = row.record;
            return (
              <li key={r.id}>
                <button type="button" onClick={() => openEvent(row)} className="grid w-full grid-cols-[4.75rem_1.25rem_2.75rem_minmax(0,1fr)_auto] items-center gap-x-3 rounded-lg px-1.5 py-2 text-left transition-colors hover:bg-surface-2">
                  <span className="tabular text-sm text-fg-3" title={formatDateTime(r.ts_utc, locale)}>{formatSmartTime(r.ts_utc, locale)}</span>
                  <span className="relative z-1 mx-auto size-2.5 rounded-full ring-4 ring-surface" style={{ background: v(LEVEL_VAR[r.risk.level] ?? "--risk-high") }} aria-hidden />
                  <RiskPill score={r.risk.score} />
                  <span className="min-w-0">
                    <span className="block truncate font-mono text-sm text-fg" title={r.summary}>{r.summary}</span>
                    <span className="block truncate text-sm text-fg-3">
                      {basename(r.workspace) || r.agent}
                      {r.risk.categories[0] ? ` · ${t.enums.category[r.risk.categories[0]] ?? r.risk.categories[0]}` : ""}
                    </span>
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    {r.actual_decision === "no_opinion" ? <DecisionBadge decision={r.simulated_decision} simulated /> : <ActualBadge decision={r.actual_decision} />}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      )}
    </AsyncView>
  );
}

export default function OverviewPage() {
  const t = useT();
  const o = t.overview;
  const locale = useLocale();
  const status = useApp((s) => s.status);
  const [win, setWin] = useState<WindowId>("24");
  const hours = Number(win);
  const stats = useAsync(() => backend.stats(hours), [hours], { refreshMs: 10_000 });

  // Live data flow: a pushed event triggers a (throttled) real re-query, so every number stays backend-derived.
  const reload = stats.reload;
  const throttle = useRef<ReturnType<typeof setTimeout> | null>(null);
  useLiveEvents(() => {
    if (throttle.current) return;
    throttle.current = setTimeout(() => {
      throttle.current = null;
      reload();
    }, 2000);
  });
  useEffect(() => () => {
    if (throttle.current) clearTimeout(throttle.current);
  }, []);

  const windows = [
    { value: "1", label: t.common.window1h }, { value: "24", label: t.common.window24h },
    { value: "168", label: t.common.window7d }, { value: "720", label: t.common.window30d },
  ] as const;
  const n = (x: number) => formatCompact(x, locale);
  const now = Date.now();

  return (
    <Page>
      <PageHeader
        title={o.title}
        description={o.description}
        actions={<Segmented label={t.common.window} value={win} onChange={setWin} options={windows} />}
      />
      <div className="space-y-5">
        <ModeHero />
        <AsyncView state={stats} skeleton={
          <div className="space-y-5">
            <div className="grid grid-cols-4 gap-4 2xl:grid-cols-8">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-25" />)}</div>
            <div className="grid gap-5 xl:grid-cols-3"><Skeleton className="h-80 xl:col-span-2" /><Skeleton className="h-80" /></div>
          </div>
        }>
          {(s) => {
            const dropped = Math.max(s.dropped_events, status?.dropped_events ?? 0);
            const lastMinute = s.per_minute.length ? (s.per_minute[s.per_minute.length - 1]?.count ?? 0) : 0;
            return (
              <div className="space-y-5">
                <div className="grid grid-cols-4 gap-4 2xl:grid-cols-8">
                  <Kpi label={o.kpiEvents} value={n(s.events_in_window)} hint={fmt(o.kpiEventsHint, { total: n(s.total_events) })} icon={Activity} tone="var(--accent-2)" onClick={() => navigate("live")} />
                  <Kpi label={o.kpiRisky} value={n(s.risky_events)} hint={o.kpiRiskyHint} icon={Gauge} tone="var(--risk-medium)" onClick={() => navigate("live", { min: "40" })} />
                  <Kpi label={o.kpiWouldBlock} value={n(s.would_block)} hint={o.kpiWouldBlockHint} icon={ShieldQuestion} tone="var(--mode-shadow)" onClick={() => navigate("live", { decision: "deny" })} />
                  <Kpi label={o.kpiBlocked} value={n(s.actually_blocked)} hint={o.kpiBlockedHint} icon={Ban} tone="var(--danger)" onClick={() => navigate("live", { actual: "deny" })} />
                  <Kpi label={o.kpiAsks} value={n(s.actually_asked)} hint={o.kpiAsksHint} icon={Hand} tone="var(--mode-interactive)" onClick={() => navigate("approvals")} />
                  <Kpi label={o.kpiSessions} value={n(s.active_sessions)} hint={o.kpiSessionsHint} icon={Users} tone="var(--accent)" onClick={() => navigate("sessions")} />
                  <Kpi label={o.kpiDegraded} value={n(s.degraded_events)} hint={o.kpiDegradedHint} icon={CircleAlert} tone={s.degraded_events > 0 ? "var(--warn)" : undefined} alert={s.degraded_events > 0} />
                  <Kpi label={o.kpiDropped} value={n(dropped)} hint={o.kpiDroppedHint} icon={TriangleAlert} tone={dropped > 0 ? "var(--warn)" : undefined} alert={dropped > 0} title={o.kpiDroppedTitle} />
                </div>

                <div className="grid gap-5 xl:grid-cols-3">
                  <Card className="xl:col-span-2" title={o.perMinuteTitle} subtitle={o.perMinuteSubtitle}
                    actions={<span className="flex items-center gap-2 text-sm text-fg-2"><span className="size-2 animate-pulse-dot rounded-full bg-ok text-ok" aria-hidden />{fmt(o.nowRate, { n: lastMinute })}</span>}>
                    <PerMinuteChart buckets={s.per_minute} now={now} />
                  </Card>
                  <Card title={o.distributionTitle} subtitle={o.distributionSubtitle}><RiskDistribution stats={s} /></Card>
                </div>

                <div className="grid gap-5 xl:grid-cols-3">
                  <Card className="xl:col-span-2" title={o.perHourTitle} subtitle={o.perHourSubtitle}>
                    <PerHourChart buckets={s.per_hour} windowHours={hours} now={now} />
                  </Card>
                  <Card title={o.categoriesTitle} subtitle={o.categoriesSubtitle}>
                    {s.by_category.length === 0 ? <p className="py-6 text-center text-base text-fg-3">{o.categoriesEmpty}</p> : (
                      <BarList
                        items={s.by_category.slice(0, 6)}
                        color={(k) => v(FAMILY_VAR[CATEGORY_FAMILY[k as RiskCategory] ?? "none"])}
                        label={(k) => ({ text: t.enums.category[k as RiskCategory] ?? k })}
                        format={(x) => formatNumber(x, locale)}
                        onClick={(k) => navigate("live", { category: k })}
                      />
                    )}
                  </Card>
                </div>

                <div className="grid gap-5 xl:grid-cols-3">
                  <Card className="xl:col-span-2" title={o.heatmapTitle} subtitle={o.heatmapSubtitle}><ActivityHeatmap buckets={s.heatmap} /></Card>
                  <Card title={o.workspacesTitle} subtitle={o.workspacesSubtitle}>
                    {s.top_workspaces.length === 0 ? <EmptyState title={t.common.noData} compact /> : (
                      <BarList
                        items={s.top_workspaces.slice(0, 6)}
                        total={s.events_in_window}
                        color={() => "var(--accent-2)"}
                        label={(k) => ({ text: basename(k) || k, title: k })}
                        format={(x) => formatNumber(x, locale)}
                      />
                    )}
                  </Card>
                </div>

                <div className="grid gap-5 xl:grid-cols-3">
                  <Card className="xl:col-span-2" title={o.timelineTitle} subtitle={o.timelineSubtitle}
                    actions={<Button size="sm" variant="ghost" onClick={() => navigate("threats")}>{t.common.viewAll}</Button>} bodyClassName="px-3.5!">
                    <SecurityTimeline />
                  </Card>
                  <Card title={<span className="flex items-center gap-2"><Timer className="size-4.5 text-fg-3" aria-hidden />{o.latencyTitle}</span>} subtitle={o.latencySubtitle}>
                    {status ? (
                      <div className="space-y-6">
                        <LatencyBlock title={o.latencyHook} l={status.hook_latency} />
                        <LatencyBlock title={o.latencyEval} l={status.eval_latency} />
                      </div>
                    ) : null}
                  </Card>
                </div>
                {s.first_event && <p className="text-sm text-fg-3">{fmt(o.firstEvent, { value: formatDateTime(s.first_event, locale) })}</p>}
              </div>
            );
          }}
        </AsyncView>
      </div>
    </Page>
  );
}
