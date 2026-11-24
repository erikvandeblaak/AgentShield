import { useEffect, useRef } from "react";
import { echarts, type EChartsCoreOption } from "../theme/echarts";
import { prefersReducedMotion } from "../theme/theme";
import { cx } from "./ui";

export interface ChartClick { seriesName?: string; name?: string; dataIndex?: number; data?: unknown; value?: unknown }

interface ChartProps {
  option: EChartsCoreOption;
  height?: number | string;
  /** Accessible description of what the chart shows (charts are canvas; this is their text alternative). */
  ariaLabel: string;
  className?: string;
  onClick?: (p: ChartClick) => void;
  /** Replace instead of merge on update (needed when the series count changes). */
  notMerge?: boolean;
}

/**
 * Thin ECharts wrapper: canvas renderer at device pixel ratio (HiDPI-crisp), resize-aware,
 * theme-aware (pass an option built from useChartTheme()), animation off for reduced motion.
 * SECURITY: tooltip formatters render HTML – escape every event-derived string (lib/escape.ts).
 */
export function Chart({ option, height = 260, ariaLabel, className, onClick, notMerge = true }: ChartProps) {
  const host = useRef<HTMLDivElement>(null);
  const chart = useRef<ReturnType<typeof echarts.init> | null>(null);
  const clickRef = useRef(onClick);
  clickRef.current = onClick;

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const instance = echarts.init(el, undefined, { renderer: "canvas" });
    chart.current = instance;
    instance.on("click", (p) => clickRef.current?.(p as ChartClick));
    const ro = new ResizeObserver(() => instance.resize());
    ro.observe(el);
    return () => {
      ro.disconnect();
      instance.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    const reduced = prefersReducedMotion();
    chart.current?.setOption(
      { animation: !reduced, animationDuration: 350, animationDurationUpdate: 250, ...option },
      { notMerge, lazyUpdate: true },
    );
  }, [option, notMerge]);

  return <div ref={host} role="img" aria-label={ariaLabel} className={cx("w-full min-w-0", className)} style={{ height }} />;
}
