import { useMemo, useState } from "react";
import { Eraser, FilePlus2, Sparkles } from "lucide-react";
import { Button, Callout, Checkbox, CodeBlock, Field, Select, TextInput, cx } from "../ui";
import {
  ACTIONS, EMPTY_RULE, EVENT_TYPES, TEMPLATES, hasMatch, isValidRuleId, ruleToToml, splitList, type RuleDraft, type TemplateId,
} from "./toml";
import { fmt, useT } from "../../i18n";
import { ALL_CATEGORIES } from "../../theme/palette";

function ChipGroup<V extends string>({ label, options, selected, onToggle, render, mono }: {
  label: string;
  options: readonly V[];
  selected: readonly V[];
  onToggle: (v: V) => void;
  render: (v: V) => string;
  mono?: boolean;
}) {
  const t = useT();
  return (
    <fieldset className="min-w-0">
      <legend className="mb-1.5 flex w-full items-baseline justify-between text-sm font-medium text-fg-2">
        {label}
        {selected.length > 0 && <span className="tabular font-normal text-fg-3">{fmt(t.policy.selectedCount, { n: selected.length })}</span>}
      </legend>
      <div className="flex flex-wrap gap-1.5">
        {options.map((o) => {
          const on = selected.includes(o);
          return (
            <button
              key={o}
              type="button"
              aria-pressed={on}
              onClick={() => onToggle(o)}
              className={cx(
                "h-7 rounded-md border px-2 text-xs transition-colors",
                mono && "font-mono",
                on ? "border-accent-2 bg-accent-2/12 font-medium text-fg" : "border-line bg-surface-2 text-fg-2 hover:border-line-strong hover:text-fg",
              )}
            >
              {render(o)}
            </button>
          );
        })}
      </div>
    </fieldset>
  );
}

const TEMPLATE_IDS = Object.keys(TEMPLATES) as TemplateId[];

/** Form → `[[rules]]` TOML block. The generated text is only inserted into the editor, never saved directly. */
export function RuleBuilder({ onInsert }: { onInsert: (block: string) => void }) {
  const t = useT();
  const p = t.policy;
  const [draft, setDraft] = useState<RuleDraft>(TEMPLATES.env);
  // List fields keep their raw text so typing a trailing comma is not fought by re-formatting.
  const [text, setText] = useState({ programs: "", path_globs: TEMPLATES.env.path_globs.join(", "), finding_ids: "" });
  const [minScore, setMinScore] = useState("");

  const load = (d: RuleDraft) => {
    setDraft(d);
    setText({ programs: d.programs.join(", "), path_globs: d.path_globs.join(", "), finding_ids: d.finding_ids.join(", ") });
    setMinScore(d.min_score == null ? "" : String(d.min_score));
  };
  const set = <K extends keyof RuleDraft>(key: K, value: RuleDraft[K]) => setDraft((d) => ({ ...d, [key]: value }));
  const setList = (key: "programs" | "path_globs" | "finding_ids", raw: string) => {
    setText((s) => ({ ...s, [key]: raw }));
    set(key, splitList(raw));
  };
  const toggle = <V extends string>(list: readonly V[], v: V): V[] => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  const idOk = isValidRuleId(draft.id.trim());
  const matchOk = hasMatch(draft);
  const toml = useMemo(() => ruleToToml(draft), [draft]);

  return (
    <div className="space-y-5">
      <div>
        <div className="mb-1.5 flex items-center gap-2 text-sm font-medium text-fg-2"><Sparkles className="size-4 text-accent-3" aria-hidden />{p.templates}</div>
        <div className="flex flex-wrap gap-1.5">
          {TEMPLATE_IDS.map((id) => (
            <button
              key={id}
              type="button"
              onClick={() => load(TEMPLATES[id])}
              className={cx(
                "h-8 rounded-lg border px-2.5 text-sm transition-colors",
                draft.id === TEMPLATES[id].id ? "border-accent-3 bg-accent-3/10 text-fg" : "border-line bg-surface-2 text-fg-2 hover:border-line-strong hover:text-fg",
              )}
            >
              {p.tpl[id]}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <Field label={p.fieldId} hint={p.fieldIdHint}>
          <TextInput mono value={draft.id} onChange={(e) => set("id", e.target.value)} aria-invalid={!idOk} />
        </Field>
        <Field label={p.fieldName}>
          <TextInput value={draft.name} onChange={(e) => set("name", e.target.value)} />
        </Field>
      </div>

      <div className="space-y-3.5 rounded-xl border border-line p-3.5">
        <div className="eyebrow">{p.sectionMatch}</div>
        <ChipGroup mono label={p.fieldEventTypes} options={EVENT_TYPES} selected={draft.event_types} onToggle={(v) => set("event_types", toggle(draft.event_types, v))} render={(v) => v} />
        <ChipGroup label={p.fieldCategories} options={ALL_CATEGORIES} selected={draft.categories} onToggle={(v) => set("categories", toggle(draft.categories, v))} render={(v) => t.enums.category[v]} />
        <div className="grid grid-cols-2 gap-3">
          <Field label={p.fieldPrograms} hint={p.fieldProgramsHint}>
            <TextInput mono value={text.programs} onChange={(e) => setList("programs", e.target.value)} />
          </Field>
          <Field label={p.fieldPathGlobs} hint={p.fieldPathGlobsHint}>
            <TextInput mono value={text.path_globs} onChange={(e) => setList("path_globs", e.target.value)} />
          </Field>
          <Field label={p.fieldFindingIds} hint={p.fieldFindingIdsHint}>
            <TextInput mono value={text.finding_ids} onChange={(e) => setList("finding_ids", e.target.value)} />
          </Field>
          <Field label={p.fieldMinScore} hint={p.fieldMinScoreHint}>
            <TextInput
              type="number"
              min={0}
              max={100}
              inputMode="numeric"
              value={minScore}
              onChange={(e) => {
                setMinScore(e.target.value);
                const n = Number(e.target.value);
                set("min_score", e.target.value.trim() === "" || !Number.isFinite(n) ? null : Math.max(0, Math.min(100, Math.round(n))));
              }}
            />
          </Field>
        </div>
      </div>

      <div className="space-y-3 rounded-xl border border-line p-3.5">
        <div className="eyebrow">{p.sectionEffect}</div>
        <div className="grid grid-cols-[minmax(0,12rem)_1fr] gap-3">
          <Field label={p.fieldAction}>
            <Select value={draft.action} onChange={(v) => set("action", v)} options={ACTIONS.map((a) => ({ value: a, label: `${t.enums.decision[a]} (${a})` }))} />
          </Field>
          <Field label={p.fieldReason} hint={p.fieldReasonHint}>
            <TextInput value={draft.reason} onChange={(e) => set("reason", e.target.value)} />
          </Field>
        </div>
        <Field label={p.fieldSuggestion} hint={p.fieldSuggestionHint}>
          <TextInput value={draft.suggestion} onChange={(e) => set("suggestion", e.target.value)} />
        </Field>
        <Checkbox checked={draft.hard} onChange={(v) => set("hard", v)}>
          <span className="font-medium text-fg">{p.fieldHard}</span> — {p.fieldHardHint}
        </Checkbox>
      </div>

      <div>
        <CodeBlock text={toml} label={p.preview} maxHeight={260} wrap={false} />
        {!idOk && <Callout tone="danger" className="mt-2.5">{p.errId}</Callout>}
        {idOk && !matchOk && <Callout tone="warn" className="mt-2.5">{p.errMatch}</Callout>}
        <div className="mt-3 flex flex-wrap gap-2">
          <Button variant="primary" icon={FilePlus2} disabled={!idOk} onClick={() => onInsert(toml)}>{p.insert}</Button>
          <Button variant="ghost" icon={Eraser} onClick={() => load(EMPTY_RULE)}>{p.reset}</Button>
        </div>
      </div>
    </div>
  );
}
