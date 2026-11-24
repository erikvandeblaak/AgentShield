import { LogoMark, Wordmark } from "../components/Logo";
import { cx } from "../components/ui";
import { useT } from "../i18n";
import { navigate, useRoute } from "../lib/router";
import { useApp } from "../store/app";
import { NAV } from "./nav";

export function Sidebar() {
  const t = useT();
  const route = useRoute();
  const version = useApp((s) => s.status?.version);
  return (
    <nav aria-label={t.shell.nav.mainNav} className="flex w-60 shrink-0 flex-col border-r border-line bg-bg-2">
      <a
        href="#/overview"
        className="flex h-16 shrink-0 items-center gap-3 px-5"
        aria-label={`${t.common.appName} — ${t.shell.nav.overview}`}
      >
        <LogoMark size={30} />
        <Wordmark />
      </a>
      <div className="min-h-0 flex-1 overflow-y-auto px-3 pb-3">
        {NAV.map((group) => (
          <div key={group.label} className="mt-4 first:mt-1">
            <div className="eyebrow px-2.5 pb-1.5">{t.shell.nav[group.label]}</div>
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const active = route.id === item.id;
                const Icon = item.icon;
                return (
                  <li key={item.id}>
                    <a
                      href={`#/${item.id}`}
                      aria-current={active ? "page" : undefined}
                      aria-keyshortcuts={`g ${item.key}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(item.id);
                      }}
                      className={cx(
                        "group relative flex h-9 items-center gap-2.5 rounded-lg px-2.5 text-base transition-colors",
                        active ? "bg-surface-2 font-medium text-fg shadow-[inset_0_0_0_1px_var(--line)]" : "text-fg-2 hover:bg-surface hover:text-fg",
                      )}
                    >
                      {active && <span className="absolute top-2 bottom-2 -left-3 w-0.75 rounded-r bg-accent" aria-hidden />}
                      <Icon className={cx("size-4.5 shrink-0", active ? "text-accent" : "text-fg-3 group-hover:text-fg-2")} aria-hidden />
                      <span className="truncate">{t.shell.nav[item.id]}</span>
                      <kbd className="ml-auto hidden font-mono text-xs text-fg-3 group-hover:inline" aria-hidden>g {item.key}</kbd>
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
      <footer className="shrink-0 border-t border-line px-5 py-3.5">
        <div className="text-sm text-fg-2">{t.common.tagline}</div>
        <div className="mt-1 text-xs text-fg-3">
          {t.common.developedBy} · {t.common.website}
        </div>
        {version && <div className="tabular mt-1 font-mono text-xs text-fg-3">v{version}</div>}
      </footer>
    </nav>
  );
}
