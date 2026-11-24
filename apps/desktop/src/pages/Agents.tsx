import { useMemo, useState } from "react";
import { Bot, CircleOff, Eye, RefreshCw, Trash2, Wrench } from "lucide-react";
import { InstallDialog } from "../components/agents/InstallDialog";
import { CapabilityBadge } from "../components/badges";
import { ConfirmDialog } from "../components/overlay";
import { Page } from "../components/Page";
import { AsyncView, Badge, Button, Callout, Card, DefList, EmptyState, Mono, PageHeader, cx } from "../components/ui";
import { fmt, useLocale, useT } from "../i18n";
import { backend } from "../lib/backend";
import { errorMessage, formatDateTime } from "../lib/format";
import { useAsync } from "../lib/hooks";
import { useApp } from "../store/app";
import type { AgentInfo, Capability } from "../lib/types";

function AgentCard({ agent, onInstall, onUninstall }: { agent: AgentInfo; onInstall: (repair: boolean) => void; onUninstall: () => void }) {
  const t = useT();
  const a = t.agents;
  const locale = useLocale();
  const integ = agent.integration;
  const healthy = agent.supported && !!integ?.installed && integ.verified && integ.problems.length === 0;
  const accent = !agent.supported ? undefined : healthy ? "var(--ok)" : integ?.installed ? "var(--warn)" : "var(--fg-3)";

  return (
    <Card accent={accent} className={cx(!agent.supported && "opacity-90")}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <div className={cx("flex size-11 shrink-0 items-center justify-center rounded-xl border", agent.supported ? "border-line-strong bg-surface-2 text-accent-2" : "border-line bg-surface-2 text-fg-3")}>
            {agent.supported ? <Bot className="size-5.5" aria-hidden /> : <CircleOff className="size-5.5" aria-hidden />}
          </div>
          <div className="min-w-0">
            <h3 className="truncate text-xl font-semibold text-fg">{agent.name}</h3>
            <code className="text-sm text-fg-3">{agent.id}</code>
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap justify-end gap-1.5">
          <Badge tone={agent.detected ? "var(--ok)" : "var(--fg-3)"} dot>{agent.detected ? a.detected : a.notDetected}</Badge>
          {agent.supported && agent.experimental && <Badge tone="var(--warn)">{a.experimental}</Badge>}
        </div>
      </div>

      {!agent.supported ? (
        <div className="mt-4 rounded-lg border border-dashed border-line-strong bg-surface-2 p-3.5">
          <div className="flex items-center gap-2 text-base font-semibold text-fg"><CircleOff className="size-4 text-fg-3" aria-hidden />{a.notSupported}</div>
          <p className="mt-1 text-base text-fg-3">{a.notSupportedBody}</p>
        </div>
      ) : null}

      <DefList
        className="mt-4"
        items={[
          { label: a.version, value: agent.version ? <span className="tabular">{agent.version}</span> : <span className="text-fg-3">–</span> },
          { label: a.executable, value: agent.executable ? <Mono text={agent.executable} /> : <span className="text-fg-3">{agent.detected ? "–" : a.notDetectedBody}</span> },
          ...(agent.supported ? [{ label: a.lastEvent, value: agent.last_event ? <span className="tabular">{formatDateTime(agent.last_event, locale)}</span> : <span className="text-fg-3">{a.noEventsYet}</span> }] : []),
        ]}
      />

      {agent.supported && (
        <div className="mt-4 border-t border-line pt-4">
          <div className="mb-2.5 flex flex-wrap items-center gap-2">
            <span className="eyebrow mr-1">{a.integration}</span>
            {!integ ? <Badge>{a.noIntegration}</Badge> : (
              <>
                <Badge tone={integ.installed ? "var(--ok)" : "var(--fg-3)"} dot>{integ.installed ? a.installed : a.notInstalled}</Badge>
                {integ.installed && <Badge tone={integ.verified ? "var(--ok)" : "var(--warn)"} title={a.verifiedHint}>{integ.verified ? a.verified : a.notVerified}</Badge>}
                {integ.installed && (
                  <Badge tone={integ.fail_closed ? "var(--danger)" : "var(--info)"} title={integ.fail_closed ? a.failClosedHint : a.failOpenHint}>
                    {integ.fail_closed ? a.failClosed : a.failOpen}
                  </Badge>
                )}
              </>
            )}
          </div>
          {integ && (
            <>
              {integ.installed ? (
                <>
                  <p className="mb-3 text-sm text-fg-3">{integ.fail_closed ? a.failClosedHint : a.failOpenHint}</p>
                  <DefList
                    items={[
                      { label: a.settingsPath, value: <Mono text={integ.settings_path} /> },
                      { label: a.hookBinary, value: integ.binary_path ? <Mono text={integ.binary_path} /> : <span className="text-fg-3">–</span> },
                      {
                        label: a.hookEvents,
                        value: integ.events.length ? (
                          <span className="flex flex-wrap gap-1">{integ.events.map((e) => <code key={e} className="rounded border border-line bg-surface-2 px-1.5 py-px text-xs text-fg-2">{e}</code>)}</span>
                        ) : <span className="text-fg-3">–</span>,
                      },
                    ]}
                  />
                </>
              ) : <p className="text-base text-fg-2">{a.notInstalledBody}</p>}
              {integ.missing_events.length > 0 && integ.installed && (
                <Callout tone="warn" title={a.missingEvents} className="mt-3">
                  <span className="mt-1 flex flex-wrap gap-1">{integ.missing_events.map((e) => <code key={e} className="rounded border border-line bg-surface px-1.5 py-px text-xs text-fg">{e}</code>)}</span>
                </Callout>
              )}
              {integ.problems.length > 0 && (
                <Callout tone="danger" title={a.problems} className="mt-3">
                  <ul className="mt-1 list-disc space-y-1 pl-4.5">{integ.problems.map((p) => <li key={p}>{p}</li>)}</ul>
                </Callout>
              )}
              <div className="mt-4 flex flex-wrap gap-2">
                {integ.installed ? (
                  <>
                    <Button icon={Wrench} onClick={() => onInstall(true)}>{a.repair}</Button>
                    <Button variant="outline-danger" icon={Trash2} onClick={onUninstall}>{a.uninstall}</Button>
                  </>
                ) : (
                  <Button variant="primary" icon={Eye} onClick={() => onInstall(false)}>{a.previewChanges}</Button>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {agent.notes.length > 0 && (
        <div className="mt-4 border-t border-line pt-3">
          <div className="eyebrow mb-1.5">{a.notes}</div>
          <ul className="space-y-1 text-base text-fg-2">{agent.notes.map((n) => <li key={n}>{n}</li>)}</ul>
        </div>
      )}
    </Card>
  );
}

function CapabilityMatrix({ agents }: { agents: AgentInfo[] }) {
  const t = useT();
  const names = useMemo(() => {
    const out: string[] = [];
    const src = agents.some((a) => a.supported) ? agents.filter((a) => a.supported) : agents;
    for (const a of src) for (const c of a.capabilities) if (!out.includes(c.capability)) out.push(c.capability);
    return out;
  }, [agents]);
  const cell = (agent: AgentInfo, name: string): Capability => {
    const exact = agent.capabilities.find((c) => c.capability === name);
    if (exact) return exact;
    // Unsupported agents usually report one blanket capability; it applies to every row.
    const blanket = !agent.supported ? agent.capabilities[0] : undefined;
    return { capability: name, status: "unsupported", reason: blanket?.reason ?? t.agents.notSupported };
  };
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[900px] border-collapse text-left text-base" aria-label={t.agents.matrixTitle}>
        <thead>
          <tr>
            <th scope="col" className="w-64 border-b border-line px-5 py-3 font-normal"><span className="eyebrow">{t.agents.capability}</span></th>
            {agents.map((a) => (
              <th key={a.id} scope="col" className="border-b border-line px-4 py-3 align-bottom font-normal">
                <div className="text-base font-semibold text-fg">{a.name}</div>
                <div className="text-sm text-fg-3">{a.supported ? (a.detected ? t.agents.detected : t.agents.notDetected) : t.enums.capability.unsupported}</div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {names.map((name) => (
            <tr key={name} className="border-b border-line/70 last:border-b-0">
              <th scope="row" className="px-5 py-3 align-top font-medium text-fg">{name}</th>
              {agents.map((a) => {
                const c = cell(a, name);
                return (
                  <td key={a.id} className="px-4 py-3 align-top">
                    <CapabilityBadge state={c.status} />
                    {a.supported && c.reason && <p className="mt-1.5 max-w-md text-sm text-fg-3">{c.reason}</p>}
                  </td>
                );
              })}
            </tr>
          ))}
          {agents.some((a) => !a.supported) && (
            <tr className="bg-surface-2/50">
              <th scope="row" className="px-5 py-3 align-top font-normal text-fg-3">{t.common.reason}</th>
              {agents.map((a) => (
                <td key={a.id} className="px-4 py-3 align-top text-sm text-fg-3">{a.supported ? "" : (a.capabilities[0]?.reason ?? t.agents.notSupported)}</td>
              ))}
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function AgentsPage() {
  const t = useT();
  const a = t.agents;
  const toast = useApp((s) => s.toast);
  const state = useAsync(() => backend.agents(), []);
  const [install, setInstall] = useState<{ agent: AgentInfo; repair: boolean } | null>(null);
  const [uninstall, setUninstall] = useState<AgentInfo | null>(null);
  const [busy, setBusy] = useState(false);

  const doUninstall = async () => {
    if (!uninstall) return;
    setBusy(true);
    try {
      const res = await backend.uninstall(uninstall.id);
      toast(res.ok ? "ok" : "warn", res.message || a.uninstalled);
      setUninstall(null);
      state.reload();
    } catch (e) {
      toast("danger", `${a.uninstallFailed}: ${errorMessage(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page>
      <PageHeader
        icon={Bot}
        title={a.title}
        description={a.description}
        actions={<Button icon={RefreshCw} loading={state.refreshing && state.data !== null} onClick={state.reload}>{t.common.refresh}</Button>}
      />
      <AsyncView state={state} isEmpty={(d) => d.length === 0} empty={<EmptyState icon={Bot} title={a.noAgents} body={a.noAgentsBody} />}>
        {(list) => {
          const sorted = [...list].sort((x, y) => Number(y.supported) - Number(x.supported) || Number(y.detected) - Number(x.detected));
          return (
            <div className="space-y-6">
              <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-2">
                {sorted.map((agent) => (
                  <AgentCard key={agent.id} agent={agent} onInstall={(repair) => setInstall({ agent, repair })} onUninstall={() => setUninstall(agent)} />
                ))}
              </div>
              <Callout tone="neutral" title={a.honestTitle}>{a.honestBody}</Callout>
              <Card title={a.matrixTitle} subtitle={a.matrixHint} padded={false} bodyClassName="pt-2">
                <CapabilityMatrix agents={sorted} />
              </Card>
            </div>
          );
        }}
      </AsyncView>

      {install && (
        <InstallDialog agent={install.agent} repair={install.repair} onClose={() => setInstall(null)} onDone={state.reload} />
      )}
      <ConfirmDialog
        open={uninstall !== null}
        danger
        busy={busy}
        title={uninstall ? fmt(a.uninstallTitle, { agent: uninstall.name }) : ""}
        confirmLabel={a.uninstallConfirm}
        onConfirm={() => void doUninstall()}
        onCancel={() => setUninstall(null)}
      >
        <p>{a.uninstallBody}</p>
        {uninstall?.integration && <Mono text={uninstall.integration.settings_path} wrap />}
      </ConfirmDialog>
    </Page>
  );
}
