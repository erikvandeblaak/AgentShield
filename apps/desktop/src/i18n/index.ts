// Typed dictionary i18n. English is the source of truth for the shape; every other language must
// satisfy `Dict` (checked by TypeScript and by the key-parity test).
// Usage:  const t = useT();  t.common.save   ·   fmt(t.common.eventsCount, { n: 3 })

import { en } from "./en";
import { nl } from "./nl";
import { useApp, type Lang } from "../store/app";

export type Dict = typeof en;

export const dictionaries: Record<Lang, Dict> = { en, nl };
export const LANGUAGES: Lang[] = ["en", "nl"];

export function dict(lang: Lang): Dict {
  return dictionaries[lang] ?? en;
}

export function useT(): Dict {
  return dict(useApp((s) => s.language));
}

/** BCP 47 locale for Intl formatting. */
export function useLocale(): string {
  return useApp((s) => s.language) === "nl" ? "nl-NL" : "en-GB";
}

export function fmt(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
}

/** Flattened key list ("common.save") for parity tests. */
export function flattenKeys(obj: unknown, prefix = ""): string[] {
  if (obj === null || typeof obj !== "object") return [prefix];
  return Object.entries(obj as Record<string, unknown>).flatMap(([k, v]) => flattenKeys(v, prefix ? `${prefix}.${k}` : k));
}
