import type { CSSProperties } from "react";
import { Ban, CircleHelp, Eye, Ghost, Hand, Lock, ShieldCheck, type LucideIcon } from "lucide-react";
import { Badge, cx } from "./ui";
import { useT } from "../i18n";
import { levelForScore } from "../lib/format";
import {
  ACTUAL_VAR, CAPABILITY_VAR, CATEGORY_FAMILY, COVERAGE_VAR, DECISION_VAR, FAMILY_VAR, LEVEL_VAR, MODE_VAR,
  OUTCOME_VAR, severityVar, v,
} from "../theme/palette";
import type {
  ActualDecision, CapabilityState, Confidence, Coverage, Mode, Outcome, Phase, PolicyDecision, RiskCategory, RiskLevel,
} from "../lib/types";

export const MODE_ICON: Record<Mode, LucideIcon> = {
  monitor: Eye,
  shadow: Ghost,
  interactive: Hand,
  enforce: ShieldCheck,
  lockdown: Lock,
};

export function ModeBadge({ mode, size = "sm", showTagline }: { mode: Mode; size?: "sm" | "lg"; showTagline?: boolean }) {
  const t = useT();
  const Icon = MODE_ICON[mode];
  const m = t.enums.mode[mode];
  if (size === "lg") {
    return (
      <span
        data-mode={mode}
        style={{ "--tone": v(MODE_VAR[mode]) } as CSSProperties}
        className="tone inline-flex h-9.5 items-center gap-2.5 rounded-lg px-3"
      >
        <Icon className="size-4.5 shrink-0" aria-hidden />
        <span className="text-sm font-bold tracking-wider">{m.banner}</span>
        {showTagline && <span className="hidden text-sm font-medium text-fg-2 xl:inline">— {m.tagline}</span>}
      </span>
    );
  }
  return (
    <Badge tone={v(MODE_VAR[mode])} icon={Icon} title={m.description}>
      <span data-mode={mode}>{m.label}</span>
    </Badge>
  );
}

/** Score pill coloured by risk band: 0–19 info, 20–39 low, 40–59 medium, 60–79 high, 80–100 critical. */
export function RiskPill({ score, showLabel, className }: { score: number; showLabel?: boolean; className?: string }) {
  const t = useT();
  const level = levelForScore(score);
  return (
    <span
      data-level={level}
      title={`${t.common.risk}: ${score} · ${t.enums.level[level]}`}
      style={{ "--tone": v(LEVEL_VAR[level]) } as CSSProperties}
      className={cx("tone tabular inline-flex h-6 min-w-9 items-center justify-center gap-1.5 rounded-md px-1.5 text-sm font-semibold", className)}
    >
      {score}
      {showLabel && <span className="text-xs font-medium">{t.enums.level[level]}</span>}
    </span>
  );
}

export function LevelBadge({ level }: { level: RiskLevel }) {
  const t = useT();
  return <Badge tone={v(LEVEL_VAR[level])} dot><span data-level={level}>{t.enums.level[level]}</span></Badge>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const t = useT();
  const label = (t.enums.severity as Record<string, string>)[severity] ?? severity;
  return <Badge tone={v(severityVar(severity))} dot>{label}</Badge>;
}

/** Policy result. `simulated` renders the honest "Would deny" wording for events that were not enforced. */
export function DecisionBadge({ decision, simulated }: { decision: PolicyDecision; simulated?: boolean }) {
  const t = useT();
  if (decision === "allow" && simulated) return <span className="text-sm text-fg-3">{t.enums.decision.allow}</span>;
  return (
    <Badge tone={v(DECISION_VAR[decision])} className={simulated ? "border-dashed" : undefined}>
      {simulated ? t.enums.would[decision] : t.enums.decision[decision]}
    </Badge>
  );
}

/** What AgentShield actually told the agent. */
export function ActualBadge({ decision }: { decision: ActualDecision }) {
  const t = useT();
  if (decision === "not_applicable") return <span className="text-sm text-fg-3" title={t.enums.actualHint.not_applicable}>–</span>;
  if (decision === "no_opinion") return <span className="text-sm text-fg-3" title={t.enums.actualHint.no_opinion}>{t.enums.actual.no_opinion}</span>;
  return (
    <Badge tone={v(ACTUAL_VAR[decision])} solid={decision === "deny"} icon={decision === "deny" ? Ban : Hand} title={t.enums.actualHint[decision]}>
      {t.enums.actual[decision]}
    </Badge>
  );
}

export function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  const t = useT();
  if (outcome === "not_applicable") return <span className="text-sm text-fg-3">–</span>;
  return <Badge tone={v(OUTCOME_VAR[outcome])} dot>{t.enums.outcome[outcome]}</Badge>;
}

export function CoverageBadge({ coverage }: { coverage: Coverage }) {
  const t = useT();
  return <Badge tone={v(COVERAGE_VAR[coverage])} title={t.enums.coverageHint[coverage]}>{t.enums.coverage[coverage]}</Badge>;
}

export function CapabilityBadge({ state, reason }: { state: CapabilityState; reason?: string }) {
  const t = useT();
  return <Badge tone={v(CAPABILITY_VAR[state])} dot title={reason} icon={state === "unverified" ? CircleHelp : undefined}>{t.enums.capability[state]}</Badge>;
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence | string }) {
  const t = useT();
  const label = (t.enums.confidence as Record<string, string>)[confidence] ?? confidence;
  const n = confidence === "high" ? 3 : confidence === "medium" ? 2 : 1;
  return (
    <span className="inline-flex items-center gap-1.5 text-sm text-fg-2" title={`${t.common.confidence}: ${label}`}>
      <span className="flex items-end gap-0.5" aria-hidden>
        {[1, 2, 3].map((i) => (
          <span key={i} className={cx("w-1 rounded-sm", i <= n ? "bg-fg-2" : "bg-line-strong")} style={{ height: 4 + i * 3 }} />
        ))}
      </span>
      {label}
    </span>
  );
}

export function CategoryChip({ category }: { category: RiskCategory }) {
  const t = useT();
  return (
    <span className="inline-flex h-6 max-w-full items-center gap-1.5 rounded-md border border-line bg-surface-2 px-2 text-xs font-medium text-fg-2">
      <span className="size-2 shrink-0 rounded-sm" style={{ background: v(FAMILY_VAR[CATEGORY_FAMILY[category] ?? "none"]) }} aria-hidden />
      <span className="truncate">{t.enums.category[category] ?? category}</span>
    </span>
  );
}

export function PhaseBadge({ phase }: { phase: Phase }) {
  const t = useT();
  const tone = phase === "pre" ? "var(--accent-2)" : phase === "post" ? "var(--accent-3)" : "var(--fg-3)";
  return <Badge tone={tone} title={t.enums.phaseLong[phase]}>{t.enums.phase[phase]}</Badge>;
}
