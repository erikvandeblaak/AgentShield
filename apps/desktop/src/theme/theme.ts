import { useEffect, useSyncExternalStore } from "react";
import { useApp, type ThemeSetting } from "../store/app";

export type ResolvedTheme = "dark" | "light";

const mq = typeof window !== "undefined" && typeof window.matchMedia === "function"
  ? window.matchMedia("(prefers-color-scheme: light)")
  : null;

function subscribeSystem(cb: () => void): () => void {
  mq?.addEventListener("change", cb);
  return () => mq?.removeEventListener("change", cb);
}

export function resolveTheme(setting: ThemeSetting, systemLight: boolean): ResolvedTheme {
  if (setting === "system") return systemLight ? "light" : "dark";
  return setting;
}

export function useResolvedTheme(): ResolvedTheme {
  const setting = useApp((s) => s.theme);
  const systemLight = useSyncExternalStore(subscribeSystem, () => mq?.matches ?? false);
  return resolveTheme(setting, systemLight);
}

/** Applies the theme to <html data-theme> and the language to <html lang>. Call once at the root. */
export function useApplyTheme(): ResolvedTheme {
  const theme = useResolvedTheme();
  const language = useApp((s) => s.language);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);
  return theme;
}

export function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}
