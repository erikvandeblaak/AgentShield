import { useEffect, useMemo, useRef, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Check, CircleCheck, Loader2, Lock, OctagonAlert, RotateCcw, Save, ScrollText, TriangleAlert } from "lucide-react";
import { DecisionBadge } from "../components/badges";
import { DataTable } from "../components/DataTable";
import { Page } from "../components/Page";
import { RuleBuilder } from "../components/policy/RuleBuilder";
import { TomlEditor } from "../components/policy/TomlEditor";
import { appendBlock } from "../components/policy/toml";
import { AsyncView, Badge, Button, Callout, Card, EmptyState, Mono, PageHeader, Select, Tabs, cx } from "../components/ui";
import { fmt, useT } from "../i18n";
import { backend } from "../lib/backend";
import { errorMessage } from "../lib/format";
import { useAsync, useDebounced } from "../lib/hooks";
import { useApp } from "../store/app";
import { DECISION_VAR, v } from "../theme/palette";
import type { PolicyDecision, PolicyInfo, RuleSummary, ValidationResult } from "../lib/types";

function ThresholdScale({ thresholds }: { thresholds: PolicyInfo["thresholds"] }) {
  const t = useT();
  const p = t.policy;
  const marks: { at: number | null; decision: PolicyDecision; label: string }[] = [
    { at: thresholds.warn_at, decision: "warn", label: p.warnAt },
    { at: thresholds.ask_at, decision: "ask", label: p.askAt },
    { at: thresholds.deny_at, decision: "deny", label: p.denyAt },
  ];
  // Build contiguous bands from the thresholds that are set.
  const set = marks.filter((m): m is { at: number; decision: PolicyDecision; label: string } => m.at != null).sort((a, b) => a.at - b.at);
  const bands: { from: number; to: number; decision: PolicyDecision }[] = [];
  let from = 0;
  let current: PolicyDecision = "allow";
  for (const m of set) {
    const at = Math.max(0, Math.min(100, m.at));
    if (at > from) bands.push({ from, to: at, decision: current });
    from = at;
    current = m.decision;
  }
  if (from < 100) bands.push({ from, to: 100, decision: current });
  const summary = marks.map((m) => `${m.label} ${m.at ?? p.thresholdNone}`).join(", ");
  return (
    <div>
      <div role="img" aria-label={`${p.thresholds}: ${summary}`} className="flex h-7 w-full gap-0.5 overflow-hidden rounded-lg">
        {bands.map((b) => (
          <div
            key={b.from}
            className="flex min-w-0 items-center justify-center text-xs font-semibold"
            style={{ width: `${b.to - b.from}%`, background: `color-mix(in srgb, ${v(DECISION_VAR[b.decision])} 22%, var(--surface-2))`, color: v(DECISION_VAR[b.decision]) }}
          >
            {b.to - b.from >= 12 && <span className="truncate px-1">{t.enums.decision[b.decision]}</span>}
          </div>
        ))}
      </div>
      <div className="tabular relative mt-1 h-4 text-xs text-fg-3">
        <span className="absolute left-0">0</span>
        {set.map((m) => <span key={m.decision} className="absolute -translate-x-1/2" style={{ left: `${m.at}%` }}>{m.at}</span>)}
        <span className="absolute right-0">100</span>
      </div>
      <dl className="mt-3 grid grid-cols-3 gap-3">
        {marks.map((m) => (
          <div key={m.decision} className="rounded-lg border border-line bg-surface-2 px-3 py-2">
            <dt className="text-sm text-fg-3">{m.label}</dt>
            <dd className={cx("tabular text-xl font-semibold", m.at == null ? "text-fg-3" : "text-fg")}>{m.at ?? "–"}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

type ValState = { status: "idle" } | { status: "validating" } | { status: "done"; result: ValidationResult } | { status: "error"; message: string };

function ValidationStatus({ state }: { state: ValState }) {
  const t = useT();
  const p = t.policy;
  if (state.status === "idle" || state.status === "validating") {
    return <div role="status" className="flex items-center gap-2 text-base text-fg-3"><Loader2 className="size-4 animate-spin" aria-hidden />{p.validating}</div>;
  }
  if (state.status === "error") return <Callout tone="danger" title={p.validationFailed}>{state.message}</Callout>;
  const { result } = state;
  return (
    <div className="space-y-2" aria-live="polite">
      {result.ok ? (
        <div className="flex items-center gap-2 text-base font-medium text-ok"><CircleCheck className="size-4.5" aria-hidden />{p.valid}</div>
      ) : (
        <Callout tone="danger" icon={OctagonAlert} title={p.invalid}>
          <code className="mt-0.5 block text-sm break-words whitespace-pre-wrap text-fg">{result.error}</code>
        </Callout>
      )}
      {result.warnings.length > 0 && (
        <Callout tone="warn" title={`${p.validationWarnings} · ${result.warnings.length}`}>
          <ul className="mt-1 list-disc space-y-0.5 pl-4.5">{result.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
        </Callout>
      )}
    </div>
  );
}

export default function PolicyPage() {
  const t = useT();
  const p = t.policy;
  const toast = useApp((s) => s.toast);
  const activePreset = useApp((s) => s.status?.preset);
  const presets = useAsync(() => backend.presets(), []);
  const policy = useAsync(() => backend.policy(), []);

  // ---- preset selection
  const [selected, setSelected] = useState<string | null>(null);
  const [activating, setActivating] = useState(false);
  const presetId = selected ?? activePreset ?? presets.data?.[0]?.id ?? "";
  const preset = presets.data?.find((x) => x.id === presetId) ?? null;
  const activate = async () => {
    setActivating(true);
    try {
      await backend.setPreset(presetId);
      await useApp.getState().refreshStatus();
      policy.reload();
      setSelected(null);
      toast("ok", fmt(p.presetChanged, { preset: preset?.title ?? presetId }));
    } catch (e) {
      toast("danger", `${p.presetFailed}: ${errorMessage(e)}`);
    } finally {
      setActivating(false);
    }
  };

  // ---- user policy editor
  const [savedText, setSavedText] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [tab, setTab] = useState<"user" | "preset">("user");
  const [saving, setSaving] = useState(false);
  const [val, setVal] = useState<ValState>({ status: "idle" });
  const loadedText = policy.data?.user_policy_text;
  const adopted = useRef(false);
  useEffect(() => {
    if (loadedText == null) return;
    // Adopt the daemon's text on first load; later reloads only move the "saved" baseline.
    if (!adopted.current) {
      adopted.current = true;
      setText(loadedText);
    }
    setSavedText(loadedText);
  }, [loadedText]);

  const dirty = savedText !== null && text !== savedText;
  const debounced = useDebounced(text, 400);
  const ready = savedText !== null;
  useEffect(() => {
    if (!ready) return;
    let cancelled = false;
    setVal({ status: "validating" });
    backend.validatePolicy(debounced)
      .then((result) => !cancelled && setVal({ status: "done", result }))
      .catch((e: unknown) => !cancelled && setVal({ status: "error", message: errorMessage(e) }));
    return () => {
      cancelled = true;
    };
  }, [debounced, ready]);

  const pendingValidation = debounced !== text || val.status !== "done";
  const valid = val.status === "done" && val.result.ok && !pendingValidation;
  const save = async () => {
    setSaving(true);
    try {
      const info = await backend.saveUserPolicy(text);
      setSavedText(info.user_policy_text);
      setText(info.user_policy_text);
      policy.reload();
      toast("ok", p.saved);
    } catch (e) {
      toast("danger", `${p.saveFailed}: ${errorMessage(e)}`);
    } finally {
      setSaving(false);
    }
  };
  const insert = (block: string) => {
    setText((cur) => appendBlock(cur, block));
    setTab("user");
    toast("info", p.inserted);
  };

  const columns = useMemo<ColumnDef<RuleSummary>[]>(() => [
    {
      id: "id", header: `${p.colId} · ${p.colName}`, accessorKey: "id",
      cell: ({ row }) => (
        <span className="block min-w-0">
          <code className="block text-sm font-medium break-all text-fg">{row.original.id}</code>
          {row.original.name && <span className="mt-0.5 block text-sm text-fg-3">{row.original.name}</span>}
        </span>
      ),
    },
    { id: "decision", header: p.colDecision, accessorKey: "decision", meta: { className: "w-24" }, cell: ({ row }) => <DecisionBadge decision={row.original.decision} /> },
    {
      id: "hard", header: p.colHard, accessorFn: (r) => Number(r.hard), meta: { className: "w-24" },
      cell: ({ row }) => (row.original.hard ? <Badge tone="var(--danger)" icon={Lock}>{p.hard}</Badge> : <span className="text-fg-3">–</span>),
    },
    {
      id: "enabled", header: p.colEnabled, accessorFn: (r) => Number(r.enabled), meta: { className: "w-28" },
      cell: ({ row }) => (row.original.enabled
        ? <span className="inline-flex items-center gap-1.5 text-sm text-ok"><Check className="size-4" aria-hidden />{t.common.enabled}</span>
        : <span className="text-sm text-fg-3">{t.common.disabled}</span>),
    },
    {
      id: "layer", header: p.colLayer, accessorKey: "layer", meta: { className: "w-28" },
      cell: ({ row }) => <Badge tone={row.original.layer === "preset" ? "var(--fg-3)" : row.original.layer === "user" ? "var(--accent-2)" : "var(--accent-3)"}>{t.enums.layer[row.original.layer]}</Badge>,
    },
  ], [p, t]);

  return (
    <Page>
      <PageHeader icon={ScrollText} title={p.title} description={p.description} />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <div className="space-y-5">
          <Card title={p.activePreset}>
            <AsyncView state={presets}>
              {(list) => (
                <>
                  <div className="flex items-center gap-2">
                    <Select
                      className="flex-1"
                      aria-label={p.presetSelect}
                      value={presetId}
                      onChange={setSelected}
                      options={list.map((x) => ({ value: x.id, label: x.id === activePreset ? `${x.title} · ${p.presetActive}` : x.title }))}
                    />
                    <Button variant="primary" disabled={!presetId || presetId === activePreset} loading={activating} onClick={() => void activate()}>
                      {activating ? p.activating : p.activate}
                    </Button>
                  </div>
                  {preset && <p className="mt-3 text-base text-fg-2">{preset.description}</p>}
                  <p className="mt-2 text-sm text-fg-3">{p.modeNote}</p>
                </>
              )}
            </AsyncView>
          </Card>

          <Card title={p.effective}>
            <AsyncView state={policy}>
              {(info) => (
                <div className="space-y-5">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <code className="text-lg font-semibold text-fg">{info.name}</code>
                    <span className="text-sm text-fg-3">{p.version} {info.version}</span>
                  </div>
                  <div>
                    <div className="mb-2 flex items-baseline justify-between gap-3">
                      <span className="eyebrow">{p.thresholds}</span>
                      <span className="text-sm text-fg-3">{p.thresholdsHint}</span>
                    </div>
                    <ThresholdScale thresholds={info.thresholds} />
                  </div>
                  <div>
                    <div className="eyebrow mb-2">{p.sources}</div>
                    <ul className="space-y-1.5">
                      {info.sources.map(([layer, source]) => (
                        <li key={`${layer}:${source}`} className="flex items-center gap-2.5">
                          <Badge tone={layer === "preset" ? "var(--fg-3)" : layer === "user" ? "var(--accent-2)" : "var(--accent-3)"}>{(t.enums.layer as Record<string, string>)[layer] ?? layer}</Badge>
                          <Mono text={source} className="min-w-0 flex-1" />
                        </li>
                      ))}
                    </ul>
                  </div>
                  {info.warnings.length > 0 ? (
                    <Callout tone="warn" icon={TriangleAlert} title={p.warnings}>
                      <ul className="mt-1 list-disc space-y-0.5 pl-4.5">{info.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
                    </Callout>
                  ) : (
                    <div className="flex items-center gap-2 text-base text-fg-3"><CircleCheck className="size-4 text-ok" aria-hidden />{p.noWarnings}</div>
                  )}
                </div>
              )}
            </AsyncView>
          </Card>
        </div>

        <Card title={p.rules} subtitle={policy.data ? fmt(p.rulesHint, { n: policy.data.rules.length }) : undefined} padded={false} bodyClassName="pt-2">
          <AsyncView state={policy}>
            {(info) => (
              <DataTable
                ariaLabel={p.rules}
                data={info.rules}
                columns={columns}
                getRowId={(r) => `${r.layer}:${r.id}`}
                maxHeight={520}
                dense
                empty={<EmptyState icon={ScrollText} title={p.noRules} body={p.noRulesBody} compact />}
              />
            )}
          </AsyncView>
        </Card>
      </div>

      <div className="mt-5 grid grid-cols-1 items-start gap-5 xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        <Card
          title={p.editorTitle}
          actions={tab === "user" && savedText !== null ? (
            <Badge tone={dirty ? "var(--warn)" : "var(--fg-3)"} dot>{dirty ? p.dirty : p.clean}</Badge>
          ) : undefined}
        >
          <Tabs label={p.editorTitle} value={tab} onChange={setTab} tabs={[{ value: "user", label: p.tabUser }, { value: "preset", label: p.tabPreset }]} />
          {tab === "user" ? (
            <div className="mt-4 space-y-3">
              {policy.data && (
                <div className="flex items-center gap-2 text-sm text-fg-3">
                  <span className="shrink-0">{p.userPath}</span>
                  <Mono text={policy.data.user_policy_path} className="min-w-0 flex-1 text-fg-2" />
                </div>
              )}
              <AsyncView state={policy}>
                {() => (savedText === null ? null : (
                  <>
                    <TomlEditor value={text} onChange={setText} ariaLabel={p.editorLabel} height={440} />
                    <ValidationStatus state={pendingValidation && val.status === "done" ? { status: "validating" } : val} />
                    <div className="flex flex-wrap items-center gap-2">
                      <Button variant="primary" icon={Save} disabled={!dirty || !valid} loading={saving} onClick={() => void save()}>{p.save}</Button>
                      <Button variant="ghost" icon={RotateCcw} disabled={!dirty} onClick={() => setText(savedText)}>{p.revert}</Button>
                    </div>
                  </>
                ))}
              </AsyncView>
            </div>
          ) : (
            <div className="mt-4 space-y-3">
              <Callout tone="neutral" icon={Lock}>{p.presetReadOnly}</Callout>
              <AsyncView state={presets}>
                {() => (preset ? <TomlEditor key={preset.id} value={preset.text} readOnly ariaLabel={`${p.presetLabel}: ${preset.id}`} height={480} /> : null)}
              </AsyncView>
            </div>
          )}
        </Card>

        <Card title={p.builderTitle} subtitle={p.builderHint}>
          <RuleBuilder onInsert={insert} />
        </Card>
      </div>
    </Page>
  );
}
