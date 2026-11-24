import { describe, expect, it } from "vitest";
import { dictionaries, flattenKeys, fmt, LANGUAGES } from "./index";

function leaves(obj: unknown, prefix = ""): [string, unknown][] {
  if (obj === null || typeof obj !== "object") return [[prefix, obj]];
  return Object.entries(obj as Record<string, unknown>).flatMap(([k, v]) => leaves(v, prefix ? `${prefix}.${k}` : k));
}

describe("i18n dictionaries", () => {
  const enKeys = flattenKeys(dictionaries.en).sort();

  it("has English and Dutch", () => {
    expect(LANGUAGES).toEqual(["en", "nl"]);
  });

  it("nl has exactly the same keys as en", () => {
    const nlKeys = flattenKeys(dictionaries.nl).sort();
    const missing = enKeys.filter((k) => !nlKeys.includes(k));
    const extra = nlKeys.filter((k) => !enKeys.includes(k));
    expect({ missing, extra }).toEqual({ missing: [], extra: [] });
  });

  it.each(LANGUAGES)("%s has only non-empty string values", (lang) => {
    const bad = leaves(dictionaries[lang]).filter(([, v]) => typeof v !== "string" || v.trim() === "").map(([k]) => k);
    expect(bad).toEqual([]);
  });

  it("uses the same placeholders in both languages", () => {
    const ph = (s: unknown) => (typeof s === "string" ? [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",") : "");
    const nl = new Map(leaves(dictionaries.nl));
    const diff = leaves(dictionaries.en).filter(([k, v]) => nl.has(k) && ph(v) !== ph(nl.get(k))).map(([k]) => k);
    expect(diff).toEqual([]);
  });
});

describe("fmt", () => {
  it("interpolates named variables", () => {
    expect(fmt("{n} events in {unit}", { n: 3, unit: "1h" })).toBe("3 events in 1h");
  });
  it("leaves unknown placeholders untouched and handles repeats", () => {
    expect(fmt("{a} {b} {a}", { a: "x" })).toBe("x {b} x");
  });
  it("does not re-interpret inserted values", () => {
    expect(fmt("{a}", { a: "{b}", b: "nope" })).toBe("{b}");
  });
});
