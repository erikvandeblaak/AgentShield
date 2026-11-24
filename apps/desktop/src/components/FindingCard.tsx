import { Lightbulb } from "lucide-react";
import { CategoryChip, ConfidenceBadge, RiskPill } from "./badges";
import { useT } from "../i18n";
import type { Finding } from "../lib/types";

/** One finding: id (raw technical id), category, score, confidence, explanation, redacted evidence, mitigation. */
export function FindingCard({ finding }: { finding: Finding }) {
  const t = useT();
  return (
    <article className="rounded-lg border border-line bg-surface-2 p-3.5">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <RiskPill score={finding.score} />
        <code className="min-w-0 truncate text-sm font-medium text-fg" title={finding.id}>{finding.id}</code>
        <span className="ml-auto"><ConfidenceBadge confidence={finding.confidence} /></span>
      </header>
      <div className="mt-2"><CategoryChip category={finding.category} /></div>
      <p className="mt-2 text-base text-fg-2">{finding.explanation}</p>
      {finding.evidence && (
        <div className="mt-2.5">
          <div className="eyebrow mb-1">{t.common.evidence}</div>
          <code className="block rounded-md border border-line bg-bg-2 px-2.5 py-1.5 text-sm break-all whitespace-pre-wrap text-fg">{finding.evidence}</code>
        </div>
      )}
      {finding.mitigation && (
        <div className="mt-2.5 flex gap-2 text-base text-fg-2">
          <Lightbulb className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />
          <span><span className="font-medium text-fg">{t.common.mitigation}: </span>{finding.mitigation}</span>
        </div>
      )}
    </article>
  );
}

export function FindingList({ findings }: { findings: Finding[] }) {
  const t = useT();
  if (findings.length === 0) return <p className="text-base text-fg-3">{t.common.noFindings}</p>;
  return <div className="space-y-2.5">{findings.map((f, i) => <FindingCard key={`${f.id}-${i}`} finding={f} />)}</div>;
}
