import { Component, Suspense, lazy, useEffect, useRef, type ComponentType, type ReactNode } from "react";
import { EventDetailPanel } from "./components/EventDetail";
import { overlayOpen } from "./components/overlay";
import { ErrorState, Spinner } from "./components/ui";
import { DemoBanner, DemoWatermark, ShortcutsDialog, Splash, Toasts } from "./layout/Chrome";
import { NAV_ITEMS } from "./layout/nav";
import { OfflineScreen } from "./layout/Offline";
import { Sidebar } from "./layout/Sidebar";
import { TopBar } from "./layout/TopBar";
import { useT } from "./i18n";
import { backend, subscribeConnection, subscribeEvents, subscribeTrayNavigate } from "./lib/backend";
import { errorMessage } from "./lib/format";
import { isTypingTarget } from "./lib/hooks";
import { ROUTES, navigate, useRoute, type RouteId } from "./lib/router";
import { useApp } from "./store/app";
import { queueLive, useLive } from "./store/live";
import { useApplyTheme } from "./theme/theme";

const PAGES: Record<RouteId, ComponentType> = {
  overview: lazy(() => import("./pages/Overview")),
  live: lazy(() => import("./pages/Live")),
  threats: lazy(() => import("./pages/Threats")),
  sessions: lazy(() => import("./pages/Sessions")),
  agents: lazy(() => import("./pages/Agents")),
  approvals: lazy(() => import("./pages/Approvals")),
  policy: lazy(() => import("./pages/Policy")),
  simulator: lazy(() => import("./pages/Simulator")),
  secrets: lazy(() => import("./pages/Secrets")),
  mcp: lazy(() => import("./pages/Mcp")),
  "supply-chain": lazy(() => import("./pages/SupplyChain")),
  network: lazy(() => import("./pages/Network")),
  reports: lazy(() => import("./pages/Reports")),
  settings: lazy(() => import("./pages/Settings")),
  about: lazy(() => import("./pages/About")),
};
const Onboarding = lazy(() => import("./pages/Onboarding"));

export const ONBOARDED_KEY = "agentshield.onboarded";
const LIVE_SEED = 500;

class PageBoundary extends Component<{ children: ReactNode; resetKey: string }, { error: string | null }> {
  override state = { error: null as string | null };
  static getDerivedStateFromError(e: unknown) {
    return { error: errorMessage(e) };
  }
  override componentDidUpdate(prev: { resetKey: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }
  override render() {
    if (this.state.error) return <ErrorState error={this.state.error} onRetry={() => this.setState({ error: null })} />;
    return this.props.children;
  }
}

/** Status polling (3 s), live subscription into the ring buffer, tray navigation, first-run onboarding. */
function useBootstrap(): void {
  const epoch = useApp((s) => s.epoch);
  const online = useApp((s) => s.booted && !s.offline);
  const demo = useApp((s) => s.demo);

  useEffect(() => {
    const { refreshStatus } = useApp.getState();
    void refreshStatus();
    const id = setInterval(() => void refreshStatus(), 3000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!online) return;
    useLive.getState().clear();
    let cancelled = false;
    backend.listEvents({ limit: LIVE_SEED }).then((rows) => {
      if (!cancelled) useLive.getState().push([...rows].reverse());
    }).catch(() => undefined);
    const unEvents = subscribeEvents(queueLive);
    const unConn = subscribeConnection((c) => useApp.getState().setConnection(c));
    return () => {
      cancelled = true;
      unEvents();
      unConn();
    };
  }, [epoch, online]);

  useEffect(() => subscribeTrayNavigate((route) => {
    const id = route.replace(/^open:/, "");
    if ((ROUTES as readonly string[]).includes(id)) navigate(id as RouteId);
  }), []);

  // First run: open onboarding once the daemon is reachable (never auto-open in Demo Mode).
  const offered = useRef(false);
  useEffect(() => {
    if (!online || demo || offered.current) return;
    offered.current = true;
    try {
      if (!localStorage.getItem(ONBOARDED_KEY)) useApp.getState().setOnboardingOpen(true);
    } catch {
      /* storage unavailable */
    }
  }, [online, demo]);
}

/** g-chords for navigation, ? for help. "/" (search) lives in the top bar, Esc in the overlay stack. */
function useGlobalKeys(): void {
  useEffect(() => {
    let pendingG = 0;
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || isTypingTarget(e.target)) return;
      if (overlayOpen()) return;
      if (e.key === "?") {
        e.preventDefault();
        useApp.getState().setShortcutsOpen(true);
        return;
      }
      const now = Date.now();
      if (e.key === "g") {
        pendingG = now;
        return;
      }
      if (now - pendingG < 1200) {
        pendingG = 0;
        const item = NAV_ITEMS.find((n) => n.key === e.key.toLowerCase());
        if (item) {
          e.preventDefault();
          navigate(item.id);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}

export default function App() {
  useApplyTheme();
  useBootstrap();
  useGlobalKeys();
  const t = useT();
  const route = useRoute();
  const booted = useApp((s) => s.booted);
  const offline = useApp((s) => s.offline);
  const demo = useApp((s) => s.demo);
  const epoch = useApp((s) => s.epoch);
  const onboardingOpen = useApp((s) => s.onboardingOpen);
  const closeDetail = useApp((s) => s.closeDetail);

  useEffect(() => {
    document.documentElement.style.setProperty("--banner-h", demo ? "36px" : "0px");
  }, [demo]);

  // The detail panel belongs to the page it was opened from.
  useEffect(() => closeDetail(), [route.id, closeDetail]);

  if (!booted) return <Splash />;

  const Current = PAGES[route.id];
  const showOffline = offline && route.id !== "about";

  return (
    <div className="app-bg flex h-full flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-[70] focus:rounded-lg focus:bg-surface focus:px-3 focus:py-2">
        {t.shell.nav.skipToContent}
      </a>
      {demo && <DemoBanner />}
      <div className="flex min-h-0 flex-1">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
          <main id="main" tabIndex={-1} className="min-h-0 flex-1 overflow-hidden outline-none">
            {showOffline ? (
              <div className="h-full overflow-y-auto"><OfflineScreen /></div>
            ) : (
              <PageBoundary resetKey={`${route.id}:${epoch}`}>
                <Suspense fallback={<Spinner />}>
                  <Current key={`${route.id}:${epoch}`} />
                </Suspense>
              </PageBoundary>
            )}
          </main>
        </div>
      </div>
      <EventDetailPanel />
      <ShortcutsDialog />
      {onboardingOpen && !offline && (
        <Suspense fallback={null}><Onboarding /></Suspense>
      )}
      {demo && <DemoWatermark />}
      <Toasts />
    </div>
  );
}
