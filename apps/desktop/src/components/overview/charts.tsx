import { useMemo } from "react";
import { Chart } from "../Chart";
import { fmt, useLocale, useT } from "../../i18n";
import { tooltipHtml } from "../../lib/escape";
import { useChartTheme, type EChartsCoreOption } from "../../theme/echarts";
import type { Bucket } from "../../lib/types";

const pad = (n: number) => String(n).padStart(2, "0");
const minuteKey = (d: Date) => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;

interface Point { t: number; count: number; risky: number; max: number }

/** Last 60 minutes, one point per minute. Minutes without a bucket really had zero recorded events. */
export function minuteSeries(buckets: Bucket[], now: number): Point[] {
  const map = new Map(buckets.map((b) => [b.key, b]));
  const end = Math.floor(now / 60_000) * 60_000;
  const out: Point[] = [];
  for (let i = 59; i >= 0; i--) {
    const t = end - i * 60_000;
    const b = map.get(minuteKey(new Date(t)));
    out.push({ t, count: b?.count ?? 0, risky: b?.risky ?? 0, max: b?.max_score ?? 0 });
  }
  return out;
}

/** Hour buckets between the first and last bucket, zero-filled (keys are UTC "YYYY-MM-DDTHH"). */
export function hourSeries(buckets: Bucket[], windowHours: number, now: number): Point[] {
  const map = new Map(buckets.map((b) => [b.key, b]));
  const end = Math.floor(now / 3600_000) * 3600_000;
  const out: Point[] = [];
  for (let i = windowHours - 1; i >= 0; i--) {
    const t = end - i * 3600_000;
    const b = map.get(minuteKey(new Date(t)).slice(0, 13));
    out.push({ t, count: b?.count ?? 0, risky: b?.risky ?? 0, max: b?.max_score ?? 0 });
  }
  return out;
}

function timeLabel(locale: string, withDate: boolean) {
  return (value: number) => {
    const d = new Date(value);
    const time = d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", hour12: false });
    return withDate ? `${d.toLocaleDateString(locale, { day: "2-digit", month: "short" })}` : time;
  };
}

export function PerMinuteChart({ buckets, now }: { buckets: Bucket[]; now: number }) {
  const t = useT();
  const locale = useLocale();
  const th = useChartTheme();
  const option = useMemo<EChartsCoreOption>(() => {
    const pts = minuteSeries(buckets, now);
    return {
      grid: { ...th.grid4, top: 36 },
      legend: { ...th.legend, top: 0, right: 0, data: [t.overview.seriesAll, t.overview.seriesRisky] },
      tooltip: {
        ...th.tooltip,
        trigger: "axis",
        axisPointer: { type: "line", lineStyle: { color: th.fg3, type: "dashed" } },
        formatter: (params: unknown) => {
          const list = params as { dataIndex: number }[];
          const p = pts[list[0]?.dataIndex ?? 0];
          if (!p) return "";
          return tooltipHtml(new Date(p.t).toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", hour12: false }), [
            { color: th.accent2, label: t.overview.seriesAll, value: p.count },
            { color: th.level.high, label: t.overview.seriesRisky, value: p.risky },
          ]);
        },
      },
      xAxis: { type: "time", ...th.timeAxis, axisLabel: { ...(th.timeAxis.axisLabel as object), formatter: timeLabel(locale, false) }, splitNumber: 6 },
      yAxis: { type: "value", ...th.valueAxis, splitNumber: 3 },
      series: [
        {
          name: t.overview.seriesAll, type: "line", showSymbol: false, lineStyle: { width: 2, color: th.accent2 }, itemStyle: { color: th.accent2 },
          areaStyle: { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: `${th.accent2}40` }, { offset: 1, color: `${th.accent2}00` }] } },
          data: pts.map((p) => [p.t, p.count]),
        },
        {
          name: t.overview.seriesRisky, type: "line", showSymbol: false, lineStyle: { width: 2, color: th.level.high }, itemStyle: { color: th.level.high },
          data: pts.map((p) => [p.t, p.risky]),
        },
      ],
    };
  }, [buckets, now, th, t, locale]);
  return <Chart option={option} height={236} ariaLabel={t.overview.perMinuteAria} />;
}

export function PerHourChart({ buckets, windowHours, now }: { buckets: Bucket[]; windowHours: number; now: number }) {
  const t = useT();
  const locale = useLocale();
  const th = useChartTheme();
  const option = useMemo<EChartsCoreOption>(() => {
    const pts = hourSeries(buckets, windowHours, now);
    const multiDay = windowHours > 24;
    const few = pts.length <= 3;
    const base = few
      ? { type: "bar", barMaxWidth: 56, itemStyle: { borderRadius: [0, 0, 0, 0] } }
      : { type: "line", showSymbol: false, lineStyle: { width: 1.5 } };
    return {
      grid: { ...th.grid4, top: 36 },
      legend: { ...th.legend, top: 0, right: 0, data: [t.overview.seriesRoutine, t.overview.seriesRisky] },
      tooltip: {
        ...th.tooltip,
        trigger: "axis",
        axisPointer: { type: few ? "shadow" : "line", lineStyle: { color: th.fg3, type: "dashed" } },
        formatter: (params: unknown) => {
          const list = params as { dataIndex: number }[];
          const p = pts[list[0]?.dataIndex ?? 0];
          if (!p) return "";
          const d = new Date(p.t);
          const title = `${d.toLocaleDateString(locale, { weekday: "short", day: "2-digit", month: "short" })} ${d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", hour12: false })}`;
          return tooltipHtml(title, [
            { color: th.level.high, label: t.overview.seriesRisky, value: p.risky },
            { color: th.series[0], label: t.overview.seriesRoutine, value: p.count - p.risky },
            { label: t.common.total, value: p.count },
          ]);
        },
      },
      xAxis: {
        type: few ? "category" : "time", ...(few ? th.categoryAxis : th.timeAxis),
        ...(few ? { data: pts.map((p) => timeLabel(locale, false)(p.t)) } : { axisLabel: { ...(th.timeAxis.axisLabel as object), formatter: timeLabel(locale, multiDay) }, splitNumber: multiDay ? 7 : 8 }),
      },
      yAxis: { type: "value", ...th.valueAxis, splitNumber: 3 },
      series: [
        {
          ...base, name: t.overview.seriesRoutine, stack: "n", itemStyle: { color: th.series[0] }, lineStyle: { width: 1.5, color: th.series[0] },
          areaStyle: { color: th.series[0], opacity: 0.28 },
          data: pts.map((p) => (few ? p.count - p.risky : [p.t, p.count - p.risky])),
        },
        {
          ...base, name: t.overview.seriesRisky, stack: "n", itemStyle: { color: th.level.high }, lineStyle: { width: 1.5, color: th.level.high },
          areaStyle: { color: th.level.high, opacity: 0.55 },
          data: pts.map((p) => (few ? p.risky : [p.t, p.risky])),
        },
      ],
    };
  }, [buckets, windowHours, now, th, t, locale]);
  return <Chart option={option} height={236} ariaLabel={t.overview.perHourAria} />;
}

/** Converts UTC "d:h" buckets to the viewer's local weekday/hour. */
export function localHeatmap(buckets: Bucket[], offsetMinutes: number): Bucket[][] {
  const shift = Math.round(offsetMinutes / 60);
  const grid: Bucket[][] = Array.from({ length: 7 }, (_, d) => Array.from({ length: 24 }, (_, h) => ({ key: `${d}:${h}`, count: 0, max_score: 0, risky: 0 })));
  for (const b of buckets) {
    const [ds, hs] = b.key.split(":");
    const d = Number(ds), h = Number(hs);
    if (!Number.isInteger(d) || !Number.isInteger(h)) continue;
    const idx = (((d * 24 + h + shift) % 168) + 168) % 168;
    const cell = grid[Math.floor(idx / 24)]?.[idx % 24];
    if (!cell) continue;
    cell.count += b.count;
    cell.risky += b.risky;
    cell.max_score = Math.max(cell.max_score, b.max_score);
  }
  return grid;
}

export function ActivityHeatmap({ buckets }: { buckets: Bucket[] }) {
  const t = useT();
  const locale = useLocale();
  const th = useChartTheme();
  const option = useMemo<EChartsCoreOption>(() => {
    const grid = localHeatmap(buckets, -new Date().getTimezoneOffset());
    // Monday first, top to bottom (ECharts draws category y-axes bottom-up).
    const order = [0, 6, 5, 4, 3, 2, 1];
    const dayName = (d: number) => new Date(Date.UTC(2024, 0, 7 + d)).toLocaleDateString(locale, { weekday: "short", timeZone: "UTC" });
    const data: [number, number, number][] = [];
    let max = 0;
    order.forEach((d, y) => {
      for (let h = 0; h < 24; h++) {
        const c = grid[d]?.[h]?.count ?? 0;
        max = Math.max(max, c);
        data.push([h, y, c]);
      }
    });
    return {
      grid: { left: 8, right: 8, top: 4, bottom: 40, containLabel: true },
      tooltip: {
        ...th.tooltip,
        formatter: (p: unknown) => {
          const [h, y] = (p as { value: [number, number, number] }).value;
          const d = order[y] ?? 0;
          const cell = grid[d]?.[h];
          return tooltipHtml(`${dayName(d)} ${pad(h)}:00–${pad((h + 1) % 24)}:00`, [
            { label: t.common.events, value: cell?.count ?? 0 },
            { label: t.overview.seriesRisky, value: cell?.risky ?? 0 },
            { label: t.common.score, value: cell?.max_score ?? 0 },
          ]);
        },
      },
      xAxis: {
        type: "category", data: Array.from({ length: 24 }, (_, h) => pad(h)), ...th.categoryAxis, axisLine: { show: false },
        axisLabel: { ...(th.categoryAxis.axisLabel as object), interval: 1 }, splitArea: { show: false },
      },
      yAxis: { type: "category", data: order.map(dayName), ...th.categoryAxis, axisLine: { show: false } },
      visualMap: {
        min: 0, max: Math.max(1, max), calculable: false, orient: "horizontal", right: 4, bottom: 0, itemWidth: 10, itemHeight: 110,
        text: [t.overview.more, t.overview.less], textStyle: { color: th.fg3, fontSize: 12, fontFamily: th.fontSans },
        inRange: { color: th.seq },
      },
      series: [{
        type: "heatmap", data, itemStyle: { borderColor: th.surface, borderWidth: 2, borderRadius: 4 },
        emphasis: { itemStyle: { borderColor: th.fg2, borderWidth: 1 } },
      }],
    };
  }, [buckets, th, t, locale]);
  return <Chart option={option} height={268} ariaLabel={fmt(t.overview.heatmapAria, {})} />;
}
