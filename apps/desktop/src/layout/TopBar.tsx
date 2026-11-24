import { useEffect, useRef, useState } from "react";
import { AlertTriangle, CircleSlash, Keyboard, Languages, Moon, Pause, Play, Search, Sun, SunMoon } from "lucide-react";
import { Badge, Button, IconButton, cx } from "../components/ui";
import { fmt, useT } from "../i18n";
import { errorMessage, formatDuration } from "../lib/format";
import { isTypingTarget } from "../lib/hooks";
import { navigate, useRoute } from "../lib/router";
import { useApp } from "../store/app";
import { ModeSwitcher } from "./ModeSwitcher";

function GlobalSearch() {
  const t = useT();
  const route = useRoute();
  const ref = useRef<HTMLInputElement>(null);
  const [q, setQ] = useState("");
  const routeQ = route.id === "live" ? (route.params.get("q") ?? "") : "";
  useEffect(() => setQ(routeQ), [routeQ]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !isTypingTarget(e.target)) {
        e.preventDefault();
        ref.current?.focus();
        ref.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <form
      role="search"
      className="relative w-full max-w-88"
      onSubmit={(e) => {
        e.preventDefault();
        navigate("live", { q: q.trim() || undefined });
      }}
    >
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-3" aria-hidden />
      <input
        ref={ref}
        type="search"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={(e) => e.key === "Escape" && ref.current?.blur()}
        placeholder={t.common.searchPlaceholder}
        aria-label={t.common.search}
        aria-keyshortcuts="/"
        spellCheck={false}
        className="h-9.5 w-full rounded-lg border border-line bg-surface pr-9 pl-9 text-base text-fg placeholder:text-fg-3 hover:border-line-strong focus:border-focus focus:outline-none"
      />
      <kbd className="pointer-events-none absolute top-1/2 right-2.5 flex size-5.5 -translate-y-1/2 items-center justify-center rounded border border-line-strong font-mono text-xs text-fg-3" aria-hidden>/</kbd>
    </form>
  );
}

export function TopBar() {
  const t = useT();
  const tb = t.shell.topbar;
  const status = useApp((s) => s.status);
  const offline = useApp((s) => s.offline);
  const demo = useApp((s) => s.demo);
  const connection = useApp((s) => s.connection);
  const theme = useApp((s) => s.theme);
  const language = useApp((s) => s.language);
  const setTheme = useApp((s) => s.setTheme);
  const setLanguage = useApp((s) => s.setLanguage);
  const setPaused = useApp((s) => s.setPaused);
  const setShortcutsOpen = useApp((s) => s.setShortcutsOpen);
  const toast = useApp((s) => s.toast);

  const online = !offline && !!status?.daemon_running;
  const nextTheme = theme === "dark" ? "light" : theme === "light" ? "system" : "dark";
  const ThemeIcon = theme === "dark" ? Moon : theme === "light" ? Sun : SunMoon;
  const themeLabel = theme === "dark" ? t.common.themeDark : theme === "light" ? t.common.themeLight : t.common.themeSystem;
  const liveLabel = demo || connection === "connected" || connection === "unknown" ? tb.liveConnected : connection === "lagged" ? tb.liveLagged : tb.liveDisconnected;
  const liveTone = demo || connection === "connected" || connection === "unknown" ? "var(--ok)" : connection === "lagged" ? "var(--warn)" : "var(--danger)";

  return (
    <header className="flex h-16 shrink-0 items-center gap-4 border-b border-line bg-bg-2/80 px-6 backdrop-blur">
      {online ? <ModeSwitcher /> : (
        <Badge tone="var(--danger)" icon={CircleSlash} className="h-9.5! px-3! text-sm!">{tb.daemonOffline}</Badge>
      )}
      {online && status?.paused && (
        <span className="flex items-center gap-2">
          <Badge tone="var(--warn)" icon={Pause} solid className="h-8! px-2.5! text-sm!" title={tb.pausedHint}>{tb.paused}</Badge>
          <Button size="sm" icon={Play} onClick={() => setPaused(false).catch((e: unknown) => toast("danger", errorMessage(e)))}>{tb.resume}</Button>
        </span>
      )}
      <div className="flex min-w-0 flex-1 justify-center"><GlobalSearch /></div>
      <div className="flex shrink-0 items-center gap-2">
        {online && status && (
          <>
            {status.degraded && (
              <Badge tone="var(--warn)" icon={AlertTriangle} title={status.degraded_reasons.join("\n")}>{tb.degraded}</Badge>
            )}
            {status.dropped_events > 0 && (
              <button type="button" onClick={() => navigate("overview")} title={tb.droppedHint} className="rounded-md">
                <Badge tone="var(--warn)" icon={AlertTriangle}>{fmt(tb.dropped, { n: status.dropped_events })}</Badge>
              </button>
            )}
            <span
              className="flex h-8 items-center gap-2 rounded-lg border border-line bg-surface px-2.5 text-sm text-fg-2"
              title={`${tb.daemonOnline}${status.uptime_s != null ? ` · ${fmt(tb.uptime, { value: formatDuration(status.uptime_s) })}` : ""}`}
            >
              <span className={cx("size-2 rounded-full", !status.paused && "animate-pulse-dot")} style={{ background: liveTone, color: liveTone }} aria-hidden />
              {liveLabel}
            </span>
          </>
        )}
        <span className="mx-1 h-6 w-px bg-line" aria-hidden />
        <button
          type="button"
          onClick={() => setLanguage(language === "en" ? "nl" : "en")}
          aria-label={`${t.common.language}: ${language === "en" ? t.common.langEn : t.common.langNl}`}
          title={t.common.language}
          className="flex h-9 items-center gap-1.5 rounded-lg px-2 text-sm font-medium text-fg-2 uppercase hover:bg-surface-2 hover:text-fg"
        >
          <Languages className="size-4.5" aria-hidden />
          {language}
        </button>
        <IconButton icon={ThemeIcon} label={`${tb.toggleTheme} (${themeLabel})`} onClick={() => setTheme(nextTheme)} />
        <IconButton icon={Keyboard} label={tb.shortcuts} onClick={() => setShortcutsOpen(true)} />
      </div>
    </header>
  );
}
