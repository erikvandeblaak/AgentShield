// Modular ECharts registration (keeps the bundle small) + the shared theme-aware option fragments.
import * as echarts from "echarts/core";
import { BarChart, GraphChart, HeatmapChart, LineChart, ScatterChart } from "echarts/charts";
import {
  AriaComponent, AxisPointerComponent, DataZoomComponent, GridComponent, LegendComponent, MarkLineComponent,
  TooltipComponent, VisualMapComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { useMemo } from "react";
import { cssVar, FAMILIES, FAMILY_VAR, LEVELS, LEVEL_VAR, MODE_VAR, type Family } from "./palette";
import { useResolvedTheme } from "./theme";
import type { Mode, RiskLevel } from "../lib/types";

echarts.use([
  LineChart, BarChart, ScatterChart, HeatmapChart, GraphChart, GridComponent, TooltipComponent, LegendComponent,
  VisualMapComponent, DataZoomComponent, MarkLineComponent, AxisPointerComponent, AriaComponent, CanvasRenderer,
]);

export { echarts };
export type { EChartsCoreOption } from "echarts/core";

export interface ChartTheme {
  name: "dark" | "light";
  fg: string;
  fg2: string;
  fg3: string;
  surface: string;
  surface2: string;
  line: string;
  grid: string;
  axis: string;
  accent: string;
  accent2: string;
  accent3: string;
  danger: string;
  warn: string;
  ok: string;
  info: string;
  series: string[];
  seq: string[];
  level: Record<RiskLevel, string>;
  mode: Record<Mode, string>;
  family: Record<Family, string>;
  fontSans: string;
  fontMono: string;
  /** Shared fragments. Spread these into options so every chart looks like one system. */
  tooltip: Record<string, unknown>;
  grid4: Record<string, unknown>;
  categoryAxis: Record<string, unknown>;
  valueAxis: Record<string, unknown>;
  timeAxis: Record<string, unknown>;
  legend: Record<string, unknown>;
}

const FONT_SANS = '"Geist Variable", "Segoe UI", system-ui, sans-serif';
const FONT_MONO = '"JetBrains Mono Variable", ui-monospace, Consolas, monospace';

export function buildChartTheme(name: "dark" | "light"): ChartTheme {
  const c = cssVar;
  const fg = c("--fg"), fg2 = c("--fg-2"), fg3 = c("--fg-3");
  const surface = c("--surface"), surface2 = c("--surface-2"), line = c("--line");
  const grid = c("--chart-grid"), axis = c("--chart-axis");
  const axisLabel = { color: axis, fontFamily: FONT_SANS, fontSize: 12 };
  return {
    name, fg, fg2, fg3, surface, surface2, line, grid, axis,
    accent: c("--accent"), accent2: c("--accent-2"), accent3: c("--accent-3"),
    danger: c("--danger"), warn: c("--warn"), ok: c("--ok"), info: c("--info"),
    series: [1, 2, 3, 4, 5, 6, 7].map((i) => c(`--series-${i}`)),
    seq: [0, 1, 2, 3, 4].map((i) => c(`--seq-${i}`)),
    level: Object.fromEntries(LEVELS.map((l) => [l, c(LEVEL_VAR[l])])) as Record<RiskLevel, string>,
    mode: Object.fromEntries(Object.entries(MODE_VAR).map(([m, v]) => [m, c(v)])) as Record<Mode, string>,
    family: Object.fromEntries(FAMILIES.map((f) => [f, c(FAMILY_VAR[f])])) as Record<Family, string>,
    fontSans: FONT_SANS,
    fontMono: FONT_MONO,
    tooltip: {
      backgroundColor: c("--surface-3"),
      borderColor: c("--line-strong"),
      borderWidth: 1,
      padding: [8, 12],
      textStyle: { color: fg, fontFamily: FONT_SANS, fontSize: 13 },
      extraCssText: "border-radius:10px;box-shadow:0 12px 32px -12px rgba(0,0,0,.45);max-width:420px;white-space:normal;",
      confine: true,
      // Never let ECharts interpolate raw strings: formatters in this app always escape (lib/escape.ts).
      renderMode: "html",
    },
    grid4: { left: 8, right: 16, top: 16, bottom: 4, containLabel: true },
    categoryAxis: {
      axisLine: { lineStyle: { color: line } },
      axisTick: { show: false },
      axisLabel,
      splitLine: { show: false },
    },
    valueAxis: {
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel,
      splitLine: { lineStyle: { color: grid } },
      minInterval: 1,
    },
    timeAxis: {
      axisLine: { lineStyle: { color: line } },
      axisTick: { show: false },
      axisLabel: { ...axisLabel, hideOverlap: true },
      splitLine: { show: false },
    },
    legend: {
      icon: "roundRect",
      itemWidth: 10,
      itemHeight: 10,
      itemGap: 16,
      textStyle: { color: fg2, fontFamily: FONT_SANS, fontSize: 12 },
      inactiveColor: fg3,
    },
  };
}

export function useChartTheme(): ChartTheme {
  const name = useResolvedTheme();
  // CSS variables are applied in an effect on <html>; Chart re-renders by key so values are fresh.
  return useMemo(() => {
    if (typeof document !== "undefined") document.documentElement.dataset.theme = name;
    return buildChartTheme(name);
  }, [name]);
}
