import { ArrowDown, CircleHelp, OctagonAlert } from "lucide-react";
import { Badge, CodeBlock, cx } from "../ui";
import { fmt, useT } from "../../i18n";
import type { ParsedCommand, ParsedSegment } from "../../lib/types";

function Segment({ seg, index }: { seg: ParsedSegment; index: number }) {
  const t = useT();
  const s = t.simulator;
  return (
    <div className="rounded-lg border border-line bg-surface-2 p-3">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
        <span className="eyebrow">{fmt(s.segment, { n: index + 1 })}</span>
        {seg.wrappers.map((w, i) => <Badge key={`${w}-${i}`} tone="var(--warn)" title={s.wrappers}>{w}</Badge>)}
        <code className="rounded-md border border-accent-2/40 bg-accent-2/10 px-2 py-0.5 text-base font-semibold text-fg" title={seg.raw_program}>{seg.program || seg.raw_program || "?"}</code>
        {seg.raw_program && seg.raw_program !== seg.program && <code className="text-sm text-fg-3">{seg.raw_program}</code>}
      </div>
      <dl className="mt-2.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-sm">
        <dt className="pt-0.5 text-fg-3">{s.args}</dt>
        <dd className="flex min-w-0 flex-wrap gap-1">
          {seg.args.length === 0 ? <span className="pt-0.5 text-fg-3">{s.noArgs}</span> : seg.args.map((a, i) => (
            <code key={i} className="max-w-full rounded border border-line bg-bg-2 px-1.5 py-0.5 break-all text-fg">{a}</code>
          ))}
        </dd>
        {seg.env_assignments.length > 0 && (
          <>
            <dt className="pt-0.5 text-fg-3">{s.env}</dt>
            <dd className="flex min-w-0 flex-wrap gap-1">{seg.env_assignments.map((e, i) => <code key={i} className="rounded border border-line bg-bg-2 px-1.5 py-0.5 break-all text-fg-2">{e}</code>)}</dd>
          </>
        )}
        {seg.redirections.length > 0 && (
          <>
            <dt className="pt-0.5 text-fg-3">{s.redirections}</dt>
            <dd className="flex min-w-0 flex-wrap gap-1">
              {seg.redirections.map((r, i) => (
                <code key={i} className="rounded border border-line bg-bg-2 px-1.5 py-0.5 break-all text-fg"><span className="text-warn">{r.op}</span> {r.target}</code>
              ))}
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}

function Connector({ pipe, op }: { pipe: boolean; op: string | undefined }) {
  const t = useT();
  return (
    <div className="flex items-center gap-2 py-1 pl-5 text-sm text-fg-3">
      <ArrowDown className="size-4" style={{ color: pipe ? "var(--accent-2)" : undefined }} aria-hidden />
      {pipe ? <span><code className="font-semibold text-accent-2">|</code> {t.simulator.pipe}</span> : <span>{fmt(t.simulator.operator, { op: op ?? ";" })}</span>}
    </div>
  );
}

/** Recursive view of a parsed command: segments, connectors, nested commands, decoded payloads, inline code. */
export function CommandTree({ parsed, depth = 0 }: { parsed: ParsedCommand; depth?: number }) {
  const t = useT();
  const s = t.simulator;
  return (
    <div className={cx("space-y-3", depth > 0 && "border-l-2 border-accent-3/40 pl-3.5")}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="var(--fg-3)">{t.enums.shell[parsed.shell]}</Badge>
      </div>
      <div>
        {parsed.segments.map((seg, i) => (
          <div key={i}>
            <Segment seg={seg} index={i} />
            {i < parsed.segments.length - 1 && <Connector pipe={seg.pipes_to_next} op={parsed.operators[i]} />}
          </div>
        ))}
      </div>
      {parsed.syntax_errors.length > 0 && (
        <ul className="space-y-1" aria-label={s.syntaxErrors}>
          {parsed.syntax_errors.map((e, i) => (
            <li key={i} className="flex gap-2 text-sm text-danger"><OctagonAlert className="mt-0.5 size-4 shrink-0" aria-hidden />{e}</li>
          ))}
        </ul>
      )}
      {parsed.decoded_payloads.map((p, i) => <CodeBlock key={`d${i}`} text={p} label={s.decoded} maxHeight={140} />)}
      {parsed.inline_code.map((p, i) => <CodeBlock key={`c${i}`} text={p} label={s.inlineCode} maxHeight={140} />)}
      {parsed.nested.map((n, i) => (
        <div key={`n${i}`}>
          <div className="eyebrow mb-1.5">{fmt(s.nested, { n: i + 1 })}</div>
          <CommandTree parsed={n} depth={depth + 1} />
        </div>
      ))}
      {parsed.uncertainties.length > 0 && (
        <ul className="space-y-1" aria-label={s.parseUncertain}>
          {parsed.uncertainties.map((u, i) => (
            <li key={i} className="flex gap-2 text-sm text-fg-2"><CircleHelp className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />{u}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
