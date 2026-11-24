import { useMemo, useState, type CSSProperties } from "react";
import { ChevronDown, Flame, ListTree, Radar, ShieldAlert, ShieldCheck, Siren, TriangleAlert } from "lucide-react";
import { ConfidenceBadge, RiskPill, SeverityBadge } from "../components/badges";
import { EventTable, type EventColumnId } from "../components/EventTable";
import { Page } from "../components/Page";
import { AsyncView, Button, Callout, Card, EmptyState, Kpi, PageHeader, SectionTitle, Skeleton, cx } from "../components/ui";
import { fmt, useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { formatDateTime, formatNumber } from "../lib/format";
import { useAsync } from "../lib/hooks";
import { navigate } from "../lib/router";
import { useApp } from "../store/app";
import { severityVar, v } from "../theme/palette";
import type { Incident } from "../lib/types";

const SEVERITIES = ["critical", "high", "medium"] as const;
const FINDINGS_LIMIT = 300;
const FINDING_COLUMNS: EventColumnId[] = ["time", "project", "session", "action", "risk", "confidence", "simulated", "actual", "outcome", "policy"];

function IncidentCard({ incident, defaultOpen }: { incident: Incident; defaultOpen: boolean }) {
  const t = useT();
  const th = t.threats;
  const locale = useLocale();
  const openEventById = useApp((s) => s.openEventById);
  const [open, setOpen] = useState(defaultOpen);
  const tone = v(severityVar(incident.severity));
  const bodyId = `incident-${incident.id}`;
  return (
    <article
      className="overflow-hidden rounded-xl border border-line bg-surface shadow-card"
      style={{ "--tone": tone, boxShadow: "inset 3px 0 0 0 var(--tone), var(--shadow-card)" } as CSSProperties}
    >
      <button
        type="button"
        aria-expanded={open}
        aria-controls={bodyId}
        aria-label={`${incident.title} — ${open ? th.collapse : th.expand}`}
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-4 py-3.5 pr-4 pl-5 text-left transition-colors hover:bg-surface-2 focus-visible:outline-offset-[-2px]"
      >
        <RiskPill score={incident.score} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-lg leading-6 font-semibold text-fg">{incident.title}</span>
          <span className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-sm text-fg-3">
            <span className="tabular">{formatDateTime(incident.ts_utc, locale)}</span>
            <code className="truncate text-sm text-fg-2" title={incident.rule_id}>{incident.rule_id}</code>
            <span>{fmt(t.common.eventsCount, { n: incident.event_ids.length })}</span>
          </span>
        </span>
        <span className="hidden shrink-0 items-center gap-3 md:flex">
          <ConfidenceBadge confidence={incident.confidence} />
          <SeverityBadge severity={incident.severity} />
        </span>
        <ChevronDown className={cx("size-4.5 shrink-0 text-fg-3 transition-transform", open && "rotate-180")} aria-hidden />
      </button>
      {open && (
        <div id={bodyId} className="animate-fade-in border-t border-line px-5 pt-4 pb-5">
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,26rem)]">
            <div className="min-w-0">
              <div className="eyebrow mb-1.5">{t.common.explanation}</div>
              <p className="text-base text-fg-2">{incident.explanation}</p>
              <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-base">
                <dt className="text-fg-3">{th.rule}</dt>
                <dd className="min-w-0"><code className="text-sm break-all text-fg">{incident.rule_id}</code></dd>
                <dt className="text-fg-3">{t.common.session}</dt>
                <dd className="min-w-0">
                  {incident.session_id ? <code className="text-sm break-all text-fg" title={incident.session_id}>{incident.session_id}</code> : <span className="text-fg-3">–</span>}
                </dd>
                <dt className="text-fg-3">{t.common.confidence}</dt>
                <dd><ConfidenceBadge confidence={incident.confidence} /></dd>
              </dl>
              {incident.session_id && (
                <Button size="sm" variant="ghost" icon={ListTree} className="mt-3 -ml-2" onClick={() => navigate("sessions", { id: incident.session_id ?? undefined })}>
                  {th.openSession}
                </Button>
              )}
            </div>
            <div className="min-w-0 space-y-4">
              <Callout tone="warn" icon={TriangleAlert} title={th.correlationTitle}>{th.correlationBody}</Callout>
              <div>
                <div className="eyebrow mb-1.5">{th.evidence}</div>
                {incident.event_ids.length === 0 ? <p className="text-base text-fg-3">{th.noEvidence}</p> : (
                  <>
                    <ul className="flex flex-wrap gap-1.5">
                      {incident.event_ids.map((id) => (
                        <li key={id}>
                          <button
                            type="button"
                            onClick={() => void openEventById(id)}
                            aria-label={`${t.common.viewEvent}: ${fmt(th.eventChip, { id })}`}
                            className="tabular inline-flex h-7 items-center rounded-md border border-line-strong bg-surface-2 px-2.5 font-mono text-sm text-fg transition-colors hover:border-accent-2 hover:bg-surface-3"
                          >
                            #{id}
                          </button>
                        </li>
                      ))}
                    </ul>
                    <p className="mt-1.5 text-sm text-fg-3">{th.evidenceHint}</p>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </article>
  );
}

export default function ThreatsPage() {
  const t = useT();
  const th = t.threats;
  const locale = useLocale();
  const incidents = useAsync(() => backend.incidents(100), [], { refreshMs: 15_000 });
  const findings = useAsync(() => backend.listEvents({ min_score: 60, phase: "pre", limit: FINDINGS_LIMIT }), [], { refreshMs: 15_000 });

  const grouped = useMemo(() => {
    const list = incidents.data ?? [];
    const known = new Set<string>(SEVERITIES);
    const groups = SEVERITIES.map((sev) => ({ sev: sev as string, items: list.filter((i) => i.severity === sev) }));
    // Never hide an incident with an unexpected severity value.
    const other = [...new Set(list.filter((i) => !known.has(i.severity)).map((i) => i.severity))];
    for (const sev of other) groups.push({ sev, items: list.filter((i) => i.severity === sev) });
    return groups;
  }, [incidents.data]);

  const count = (sev: string) => grouped.find((g) => g.sev === sev)?.items.length ?? 0;
  const num = (n: number | null) => (n == null ? "–" : formatNumber(n, locale));
  const total = incidents.data ? incidents.data.length : null;
  const firstId = grouped.find((g) => g.items.length > 0)?.items[0]?.id;

  return (
    <Page>
      <PageHeader icon={ShieldAlert} title={th.title} description={th.description} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <Kpi label={th.kpiIncidents} value={num(total)} hint={th.kpiIncidentsHint} icon={Radar} />
        <Kpi label={th.kpiCritical} value={num(total == null ? null : count("critical"))} icon={Siren} tone="var(--risk-critical)" alert={count("critical") > 0} />
        <Kpi label={th.kpiHigh} value={num(total == null ? null : count("high"))} icon={Flame} tone="var(--risk-high)" />
        <Kpi label={th.kpiMedium} value={num(total == null ? null : count("medium"))} icon={TriangleAlert} tone="var(--risk-medium)" />
        <Kpi label={th.kpiFindings} value={num(findings.data ? findings.data.length : null)} hint={th.kpiFindingsHint} icon={ShieldAlert} tone="var(--risk-high)" />
      </div>

      <div className="mt-8">
        <SectionTitle hint={th.incidentsHint}>{th.incidentsTitle}</SectionTitle>
        <AsyncView
          state={incidents}
          skeleton={<div className="space-y-2.5"><Skeleton className="h-16" /><Skeleton className="h-16" /><Skeleton className="h-16" /></div>}
          isEmpty={(d) => d.length === 0}
          empty={<Card><EmptyState icon={ShieldCheck} title={th.noIncidents} body={th.noIncidentsBody} compact /></Card>}
        >
          {() => (
            <div className="space-y-6">
              {grouped.filter((g) => g.items.length > 0).map((g) => (
                <section key={g.sev} aria-label={`${(t.enums.severity as Record<string, string>)[g.sev] ?? g.sev} — ${fmt(th.groupCount, { n: g.items.length })}`}>
                  <div className="mb-2 flex items-center gap-3">
                    <SeverityBadge severity={g.sev} />
                    <span className="tabular text-sm text-fg-3">{fmt(th.groupCount, { n: g.items.length })}</span>
                    <span className="h-px flex-1 bg-line" aria-hidden />
                  </div>
                  <div className="space-y-2.5">
                    {g.items.map((incident) => <IncidentCard key={incident.id} incident={incident} defaultOpen={incident.id === firstId} />)}
                  </div>
                </section>
              ))}
            </div>
          )}
        </AsyncView>
      </div>

      <div className="mt-9">
        <SectionTitle hint={th.findingsHint}>{th.findingsTitle}</SectionTitle>
        <Card padded={false}>
          <AsyncView
            state={findings}
            isEmpty={(d) => d.length === 0}
            empty={<EmptyState icon={ShieldCheck} title={th.noFindings} body={th.noFindingsBody} compact />}
          >
            {(rows) => (
              <EventTable
                rows={rows}
                columns={FINDING_COLUMNS}
                height={Math.min(520, 40 + rows.length * 42 + (rows.length >= FINDINGS_LIMIT ? 44 : 2))}
                ariaLabel={th.findingsLabel}
                footer={rows.length >= FINDINGS_LIMIT ? fmt(th.findingsLimit, { n: FINDINGS_LIMIT }) : undefined}
              />
            )}
          </AsyncView>
        </Card>
      </div>
    </Page>
  );
}
