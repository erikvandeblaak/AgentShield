import { create } from "zustand";
import { backend, isDemo, setDemoFlag } from "../lib/backend";
import { errorMessage } from "../lib/format";
import type { Config, EventRow, Mode, Status } from "../lib/types";

export type ThemeSetting = Config["theme"];
export type Lang = Config["language"];

const PREFS_KEY = "agentshield.prefs";

interface Prefs { theme: ThemeSetting; language: Lang }

function loadPrefs(): Prefs {
  try {
    const raw = JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}") as Partial<Prefs>;
    return {
      theme: raw.theme === "light" || raw.theme === "system" ? raw.theme : "dark",
      language: raw.language === "nl" ? "nl" : "en",
    };
  } catch {
    return { theme: "dark", language: "en" };
  }
}

function savePrefs(p: Prefs): void {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(p));
  } catch {
    /* ignore */
  }
}

export interface Toast { id: number; tone: "ok" | "warn" | "danger" | "info"; text: string }

interface AppState {
  demo: boolean;
  /** Bumped whenever all data must be refetched (demo toggled, data deleted, daemon (re)connected). */
  epoch: number;
  booted: boolean; // first status attempt finished
  status: Status | null;
  offline: boolean;
  statusError: string | null;
  config: Config | null;
  theme: ThemeSetting;
  language: Lang;
  connection: string; // live subscription: connected | disconnected | lagged | unknown
  detail: EventRow | null;
  detailLoading: boolean;
  toasts: Toast[];
  onboardingOpen: boolean;
  shortcutsOpen: boolean;

  refreshStatus: () => Promise<void>;
  loadConfig: () => Promise<void>;
  patchConfig: (patch: Partial<Config>) => Promise<void>;
  setTheme: (t: ThemeSetting) => void;
  setLanguage: (l: Lang) => void;
  setDemo: (on: boolean) => void;
  setMode: (m: Mode) => Promise<void>;
  setPaused: (p: boolean) => Promise<void>;
  setStatus: (s: Status) => void;
  setConnection: (c: string) => void;
  bumpEpoch: () => void;
  openEvent: (row: EventRow) => void;
  openEventById: (id: number) => Promise<void>;
  closeDetail: () => void;
  setOnboardingOpen: (open: boolean) => void;
  setShortcutsOpen: (open: boolean) => void;
  toast: (tone: Toast["tone"], text: string) => void;
  dismissToast: (id: number) => void;
}

let toastId = 0;
const prefs = loadPrefs();

export const useApp = create<AppState>((set, get) => ({
  demo: isDemo(),
  epoch: 0,
  booted: false,
  status: null,
  offline: false,
  statusError: null,
  config: null,
  theme: prefs.theme,
  language: prefs.language,
  connection: "unknown",
  detail: null,
  detailLoading: false,
  toasts: [],
  onboardingOpen: false,
  shortcutsOpen: false,

  refreshStatus: async () => {
    try {
      const status = await backend.status();
      const wasOffline = get().offline || !get().booted;
      const running = status.daemon_running;
      set((s) => ({
        status, booted: true, offline: !running, statusError: running ? null : s.statusError,
        epoch: running && wasOffline && s.booted ? s.epoch + 1 : s.epoch,
      }));
      if (running && (wasOffline || !get().config)) void get().loadConfig();
    } catch (e) {
      set({ booted: true, offline: true, statusError: errorMessage(e) });
    }
  },

  loadConfig: async () => {
    try {
      const config = await backend.config();
      set({ config });
      // In real mode the daemon config is the source of truth for language/theme.
      if (!get().demo) {
        set({ theme: config.theme, language: config.language });
        savePrefs({ theme: config.theme, language: config.language });
      }
    } catch {
      /* offline: keep local prefs */
    }
  },

  patchConfig: async (patch) => {
    const config = await backend.setConfig(patch);
    set({ config });
  },

  setTheme: (theme) => {
    set({ theme });
    savePrefs({ theme, language: get().language });
    if (!get().offline) void backend.setConfig({ theme }).then((config) => set({ config })).catch(() => undefined);
  },

  setLanguage: (language) => {
    set({ language });
    savePrefs({ theme: get().theme, language });
    if (!get().offline) void backend.setConfig({ language }).then((config) => set({ config })).catch(() => undefined);
  },

  setDemo: (on) => {
    setDemoFlag(on);
    set((s) => ({
      demo: on, epoch: s.epoch + 1, status: null, config: null, booted: false, offline: false, statusError: null,
      detail: null, connection: "unknown",
    }));
    void get().refreshStatus();
  },

  setMode: async (mode) => {
    const status = await backend.setMode(mode);
    set({ status });
  },

  setPaused: async (paused) => {
    const status = await backend.setPaused(paused);
    set({ status });
  },

  setStatus: (status) => set({ status, offline: !status.daemon_running, booted: true }),
  setConnection: (connection) => set({ connection }),
  bumpEpoch: () => set((s) => ({ epoch: s.epoch + 1 })),

  openEvent: (row) => set({ detail: row, detailLoading: false }),
  openEventById: async (id) => {
    set({ detailLoading: true });
    try {
      const row = await backend.getEvent(id);
      if (row) set({ detail: row, detailLoading: false });
      else {
        set({ detailLoading: false });
        const { dict, fmt } = await import("../i18n");
        get().toast("warn", fmt(dict(get().language).common.eventNotFound, { id }));
      }
    } catch (e) {
      set({ detailLoading: false });
      get().toast("danger", errorMessage(e));
    }
  },
  closeDetail: () => set({ detail: null }),
  setOnboardingOpen: (onboardingOpen) => set({ onboardingOpen }),
  setShortcutsOpen: (shortcutsOpen) => set({ shortcutsOpen }),

  toast: (tone, text) => {
    const id = ++toastId;
    set((s) => ({ toasts: [...s.toasts.slice(-3), { id, tone, text }] }));
    setTimeout(() => get().dismissToast(id), 5000);
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
