import type { ReactNode } from "react";
import { ArrowRight, CircleHelp, ListTree } from "lucide-react";
import {
  ActualBadge, CategoryChip, ConfidenceBadge, CoverageBadge, DecisionBadge, ModeBadge, OutcomeBadge, PhaseBadge, RiskPill,
} from "./badges";
import { FindingList } from "./FindingCard";
import { SidePanel } from "./overlay";
import { Button, CodeBlock, CopyButton, DefList, cx } from "./ui";
import { fmt, useLocale, useT } from "../i18n";
import { actionTarget, basename, formatDateTime, formatLatency, levelForScore, prettyJson, truncateMiddle } from "../lib/format";
import { navigate } from "../lib/router";
import { useApp } from "../store/app";
import { LEVEL_VAR, v } from "../theme/palette";
import type { EventRow } from "../lib/types";

function Section({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="border-b border-line px-5 py-4 last:border-b-0">
      <div className="mb-2.5 flex items-center justify-between gap-3">
        <h3 className="eyebrow">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  );
}

function Hash({ value }: { value: string }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1">
      <code className="truncate text-sm text-fg-2" title={value}>{truncateMiddle(value, 28)}</code>
      <CopyButton text={value} />
    </span>
  );
}

export function EventDetailBody({ row }: { row: EventRow }) {
  const t = useT();
  const d = t.shell.detail;
  const locale = useLocale();
  const r = row.record;
  const target = actionTarget(r.action);
  const level = levelForScore(r.risk.score);
  const isPre = r.phase === "pre";

  return (
    <div>
      <Section title={d.what}>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <RiskPill score={r.risk.score} showLabel />
          <PhaseBadge phase={r.phase} />
          <ModeBadge mode={r.mode} />
          <CoverageBadge coverage={r.coverage} />
        </div>
        {target ? <CodeBlock text={target} maxHeight={160} label={d.target} /> : <p className="text-base text-fg-2">{r.summary}</p>}
        <DefList
          className="mt-3"
          items={[
            { label: t.common.time, value: <span className="tabular">{formatDateTime(r.ts_utc, locale)}</span> },
            { label: t.common.agent, value: <>{r.agent}{r.agent_version ? <span className="text-fg-3"> · {r.agent_version}</span> : null}</> },
            { label: t.common.project, value: r.workspace ? <span title={r.workspace}><span className="font-medium">{basename(r.workspace)}</span> <code className="text-sm text-fg-3">{r.workspace}</code></span> : "–" },
            { label: t.common.session, value: r.session_id ? <code className="text-sm break-all">{r.session_id}</code> : "–" },
            { label: t.common.action, value: <><code className="text-sm">{r.action_type}</code>{r.tool ? <span className="text-fg-3"> · {r.tool}</span> : null}</> },
            { label: d.nativeEvent, value: <code className="text-sm">{r.hook_event}</code> },
            { label: t.common.latency, value: <span className="tabular">{formatLatency(r.latency_us)}</span> },
          ]}
        />
        {r.session_id && (
          <Button size="sm" variant="ghost" icon={ListTree} className="mt-3 -ml-2" onClick={() => navigate("sessions", { id: r.session_id ?? undefined })}>
            {d.openSession}
          </Button>
        )}
      </Section>

      <Section title={d.intentVsObserved}>
        <div className="grid grid-cols-[1fr_auto_1fr] items-stretch gap-2">
          <div className={cx("rounded-lg border p-3", isPre ? "border-accent-2/40 bg-accent-2/5" : "border-line bg-surface-2")}>
            <div className="text-sm font-semibold text-fg">{d.intended}</div>
            <p className="mt-0.5 text-sm text-fg-3">{d.intendedBody}</p>
            <div className="mt-2.5 flex flex-wrap items-center gap-2">
              {r.phase === "lifecycle" ? <span className="text-sm text-fg-3">{d.notDecisionPoint}</span> : r.phase === "post" ? <span className="text-sm text-fg-3">{d.observedIsPost}</span> : <OutcomeBadge outcome={r.outcome} />}
            </div>
          </div>
          <ArrowRight className="size-4 self-center text-fg-3" aria-hidden />
          <div className={cx("rounded-lg border p-3", r.phase === "post" ? "border-accent-3/40 bg-accent-3/5" : "border-line bg-surface-2")}>
            <div className="text-sm font-semibold text-fg">{d.observed}</div>
            <p className="mt-0.5 text-sm text-fg-3">{d.observedBody}</p>
            <div className="mt-2.5 flex flex-wrap items-center gap-2">
              {r.phase === "post" ? <OutcomeBadge outcome={r.outcome} />
                : row.observed_outcome ? <OutcomeBadge outcome={row.observed_outcome} />
                : <span className="flex items-center gap-1.5 text-sm text-fg-3"><CircleHelp className="size-4" aria-hidden />{r.phase === "lifecycle" ? d.notDecisionPoint : d.observedMissing}</span>}
            </div>
          </div>
        </div>
      </Section>

      <Section title={d.riskScore} aside={<ConfidenceBadge confidence={r.risk.confidence} />}>
        <div className="flex items-center gap-4">
          <div className="tabular text-4xl leading-none font-semibold" style={{ color: v(LEVEL_VAR[level]) }}>{r.risk.score}</div>
          <div className="min-w-0 flex-1">
            <div className="relative h-2 rounded-full bg-surface-3">
              <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${r.risk.score}%`, background: v(LEVEL_VAR[level]) }} />
              {[20, 40, 60, 80].map((x) => <span key={x} className="absolute inset-y-0 w-px bg-surface" style={{ left: `${x}%` }} />)}
            </div>
            <div className="mt-1.5 text-sm text-fg-2">{t.enums.level[level]}</div>
          </div>
        </div>
        {r.risk.categories.length > 0 && <div className="mt-3 flex flex-wrap gap-1.5">{r.risk.categories.map((c) => <CategoryChip key={c} category={c} />)}</div>}
        {r.risk.explanation.length > 0 && (
          <>
            <div className="mt-4 mb-1.5 text-sm font-medium text-fg-2">{d.scoreSteps}</div>
            <ol className="space-y-1.5">
              {r.risk.explanation.map((step, i) => (
                <li key={i} className="flex gap-2.5 text-base text-fg-2">
                  <span className="tabular mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full bg-surface-3 text-xs text-fg-2">{i + 1}</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </>
        )}
      </Section>

      <Section title={`${t.common.findings} · ${r.risk.findings.length}`}>
        <FindingList findings={r.risk.findings} />
      </Section>

      <Section title={d.uncertainties}>
        {r.risk.uncertainties.length === 0 ? <p className="text-base text-fg-3">{d.noUncertainties}</p> : (
          <ul className="space-y-1.5">
            {r.risk.uncertainties.map((u, i) => (
              <li key={i} className="flex gap-2 text-base text-fg-2"><CircleHelp className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />{u}</li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={d.policyOutcome}>
        <DefList
          items={[
            { label: d.simulated, value: isPre ? <DecisionBadge decision={r.simulated_decision} /> : <span className="text-fg-3">{d.notDecisionPoint}</span> },
            { label: d.actual, value: <span className="inline-flex flex-col gap-1"><span><ActualBadge decision={r.actual_decision} /></span><span className="text-sm text-fg-3">{t.enums.actualHint[r.actual_decision]}</span></span> },
            ...(r.decision_reason ? [{ label: t.common.reason, value: r.decision_reason }] : []),
            { label: d.modeAtTime, value: <ModeBadge mode={r.mode} /> },
            { label: d.policyVersion, value: <><code className="text-sm">{r.policy_name}</code> <span className="text-fg-3">· {r.policy_version}</span></> },
            { label: t.common.coverage, value: <span className="inline-flex flex-col gap-1"><span><CoverageBadge coverage={r.coverage} /></span><span className="text-sm text-fg-3">{t.enums.coverageHint[r.coverage]}</span></span> },
          ]}
        />
        <div className="mt-3 mb-1.5 text-sm font-medium text-fg-2">{d.matchedRules}</div>
        {r.matched_rules.length === 0 ? <p className="text-base text-fg-3">{d.noRules}</p> : (
          <ul className="flex flex-wrap gap-1.5">
            {r.matched_rules.map((id) => <li key={id}><code className="rounded-md border border-line bg-surface-2 px-2 py-1 text-sm text-fg">{id}</code></li>)}
          </ul>
        )}
      </Section>

      <Section title={d.input}>
        <CodeBlock text={prettyJson(r.input_redacted)} maxHeight={280} />
        <p className="mt-2 text-sm text-fg-3">{d.inputNote}</p>
      </Section>

      <Section title={d.chain}>
        <DefList
          items={[
            { label: d.prevHash, value: <Hash value={r.prev_hash} /> },
            { label: d.hash, value: <Hash value={r.hash} /> },
            { label: d.uuid, value: <Hash value={r.uuid} /> },
            ...(r.correlation_id ? [{ label: d.correlation, value: <Hash value={r.correlation_id} /> }] : []),
            { label: t.common.status, value: <span className="text-fg-2">{r.via_daemon ? d.viaDaemon : d.viaFallback} · {fmt(d.schema, { n: r.schema_version })}</span> },
          ]}
        />
        <p className="mt-2 text-sm text-fg-3">{d.chainNote}</p>
      </Section>
    </div>
  );
}

/** Global right-hand detail panel. Open it from anywhere with useApp().openEvent(row) / openEventById(id). */
export function EventDetailPanel() {
  const t = useT();
  const row = useApp((s) => s.detail);
  const close = useApp((s) => s.closeDetail);
  return (
    <SidePanel
      open={row !== null}
      onClose={close}
      title={row ? fmt(t.shell.detail.title, { id: row.record.id }) : ""}
      subtitle={row ? <span className="block truncate font-mono" title={row.record.summary}>{row.record.summary}</span> : null}
    >
      {row && <EventDetailBody row={row} />}
    </SidePanel>
  );
}
