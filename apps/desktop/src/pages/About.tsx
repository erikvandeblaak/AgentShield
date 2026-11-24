import { Ban, Check, HeartHandshake, Lock, Scale } from "lucide-react";
import { LogoMark } from "../components/Logo";
import { Page } from "../components/Page";
import { OSS_COMPONENTS } from "../components/settings/oss";
import { Badge, Callout, Card, DefList } from "../components/ui";
import { useT } from "../i18n";
import { formatDuration } from "../lib/format";
import { useApp } from "../store/app";

function BulletList({ items, icon: Icon, tone }: { items: string[]; icon: typeof Check; tone: string }) {
  return (
    <ul className="space-y-2.5">
      {items.map((line) => (
        <li key={line} className="flex gap-2.5 text-base text-fg-2">
          <Icon className="mt-0.5 size-4.5 shrink-0" style={{ color: tone }} aria-hidden />
          <span>{line}</span>
        </li>
      ))}
    </ul>
  );
}

export default function AboutPage() {
  const t = useT();
  const a = t.about;
  const status = useApp((s) => s.status);
  const offline = useApp((s) => s.offline);
  const s = offline ? null : status;
  const na = <span className="text-fg-3">{t.common.notAvailable}</span>;
  const mono = (value: string | number | null | undefined) => (value == null || value === "" ? na : <code className="font-mono text-sm">{value}</code>);

  return (
    <Page>
      <h1 className="sr-only">{a.title}</h1>
      <section className="relative overflow-hidden rounded-2xl border border-line bg-surface px-8 py-9 shadow-card">
        <div aria-hidden className="pointer-events-none absolute -top-20 -right-10 text-fg opacity-[0.05]"><LogoMark size={360} mono /></div>
        <div className="relative flex flex-wrap items-center gap-7">
          <LogoMark size={92} />
          <div className="min-w-0">
            <div className="text-4xl leading-tight tracking-tight text-fg">
              <span className="font-semibold">Agent</span><span className="text-fg-2">Shield</span>
            </div>
            <p className="mt-1 text-xl font-medium text-fg">{t.common.tagline}</p>
            <p className="mt-1 text-base text-fg-3">{t.common.subtitle}</p>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              {s?.version && <Badge tone="var(--accent)">v{s.version}</Badge>}
              <Badge tone="var(--fg-2)" icon={Scale}>Apache-2.0</Badge>
              <span className="ml-1 text-sm text-fg-2">{t.common.developedBy} — {t.common.website}</span>
            </div>
          </div>
        </div>
      </section>

      <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Card title={a.versionInfo}>
          {!s && <p className="mb-3 text-sm text-fg-3">{a.versionOffline}</p>}
          <DefList
            items={[
              { label: a.appVersion, value: mono(s?.version) },
              { label: a.build, value: mono(s?.build) },
              { label: a.daemonVersion, value: mono(s?.daemon_version) },
              { label: a.pid, value: mono(s?.pid) },
              { label: a.uptime, value: s?.uptime_s != null ? <span className="tabular">{formatDuration(s.uptime_s)}</span> : na },
            ]}
          />
        </Card>
        <Card title={a.license} subtitle={a.licenseName}>
          <p className="text-base text-fg-2">{a.licenseBody}</p>
        </Card>
        <Card title={a.credits}>
          <div className="flex gap-3">
            <HeartHandshake className="mt-0.5 size-5 shrink-0 text-accent-2" aria-hidden />
            <div className="text-base text-fg-2">
              <p className="text-fg">{a.creditsBody}</p>
              <p className="font-mono text-sm text-fg-2">{a.creditsSite}</p>
              <p className="mt-2 text-sm text-fg-3">{a.creditsLogo}</p>
            </div>
          </div>
        </Card>
      </div>

      <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-2">
        <Card title={a.privacy} subtitle={a.privacyLead}>
          <BulletList icon={Lock} tone="var(--ok)" items={[a.privacy1, a.privacy2, a.privacy3, a.privacy4, a.privacy5]} />
        </Card>
        <Card title={a.notTitle} subtitle={a.notLead}>
          <BulletList icon={Ban} tone="var(--warn)" items={[a.not1, a.not2, a.not3, a.not4]} />
        </Card>
      </div>

      <Card className="mt-5" title={a.oss} subtitle={a.ossHint} padded={false}>
        <div className="overflow-x-auto pt-2">
          <table className="w-full border-collapse text-left text-base">
            <thead>
              <tr>
                {[a.ossName, a.ossUse, a.ossLicense].map((h) => (
                  <th key={h} scope="col" className="h-10 border-b border-line px-5 font-normal"><span className="eyebrow">{h}</span></th>
                ))}
              </tr>
            </thead>
            <tbody>
              {OSS_COMPONENTS.map((c) => (
                <tr key={c.name} className="border-b border-line/70 last:border-b-0">
                  <td className="px-5 py-2.5"><code className="font-mono text-sm text-fg">{c.name}</code></td>
                  <td className="px-5 py-2.5 text-fg-2">{a[c.use]}</td>
                  <td className="px-5 py-2.5"><span className="font-mono text-sm text-fg-2">{c.license}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="px-5 pt-3 pb-5"><Callout tone="neutral">{a.ossRust}</Callout></div>
      </Card>
    </Page>
  );
}
