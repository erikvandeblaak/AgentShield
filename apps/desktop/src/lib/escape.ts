// ECharts tooltips render HTML. Every event-derived string that ends up in a tooltip
// formatter MUST pass through escapeHtml first.

const MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "`": "&#96;",
};

export function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"'`]/g, (c) => MAP[c] ?? c);
}

/** Tagged template: interpolations are escaped, the literal parts are trusted markup. */
export function safeHtml(strings: TemplateStringsArray, ...values: unknown[]): string {
  let out = "";
  strings.forEach((s, i) => {
    out += s;
    if (i < values.length) out += escapeHtml(values[i]);
  });
  return out;
}

export interface TooltipRow { color?: string; label: string; value: string | number }

/** Builds tooltip markup with every dynamic string escaped. Colours must come from the theme, not from data. */
export function tooltipHtml(title: string, rows: TooltipRow[], footer?: string): string {
  const body = rows
    .map((r) => {
      const dot = r.color ? `<span style="display:inline-block;width:9px;height:9px;border-radius:3px;background:${escapeHtml(r.color)};margin-right:8px"></span>` : "";
      return `<div style="display:flex;align-items:center;justify-content:space-between;gap:20px;margin-top:4px"><span>${dot}${escapeHtml(r.label)}</span><strong style="font-variant-numeric:tabular-nums">${escapeHtml(r.value)}</strong></div>`;
    })
    .join("");
  const foot = footer ? `<div style="margin-top:6px;opacity:.7;font-size:12px">${escapeHtml(footer)}</div>` : "";
  return `<div style="font-weight:600">${escapeHtml(title)}</div>${body}${foot}`;
}
