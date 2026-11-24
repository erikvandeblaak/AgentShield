import { useT } from "../i18n";
import { levelForScore } from "../lib/format";
import { LEVEL_VAR, v } from "../theme/palette";

const BANDS: [number, number, string][] = [
  [0, 20, "--risk-informational"],
  [20, 40, "--risk-low"],
  [40, 60, "--risk-medium"],
  [60, 80, "--risk-high"],
  [80, 100, "--risk-critical"],
];

function polar(cx: number, cy: number, r: number, t: number): [number, number] {
  // t: 0..100 mapped onto a 240° arc starting at 150°.
  const a = ((150 + (t / 100) * 240) * Math.PI) / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function arc(cx: number, cy: number, r: number, from: number, to: number): string {
  const [x1, y1] = polar(cx, cy, r, from);
  const [x2, y2] = polar(cx, cy, r, to);
  const large = ((to - from) / 100) * 240 > 180 ? 1 : 0;
  return `M${x1.toFixed(2)} ${y1.toFixed(2)}A${r} ${r} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

/** Risk score gauge (0–100) with the five risk bands. Pure SVG: crisp at any DPI. */
export function RiskGauge({ score, size = 200 }: { score: number; size?: number }) {
  const t = useT();
  const s = Math.max(0, Math.min(100, score));
  const level = levelForScore(s);
  const color = v(LEVEL_VAR[level]);
  const [nx, ny] = polar(100, 100, 78, s);
  return (
    <div className="relative" style={{ width: size, height: size * 0.8 }}>
      <svg viewBox="0 0 200 160" width={size} height={size * 0.8} role="img" aria-label={`${t.common.risk} ${s} / 100 · ${t.enums.level[level]}`}>
        {BANDS.map(([from, to, cssVar]) => (
          <path key={cssVar} d={arc(100, 100, 78, from + 0.8, to - 0.8)} fill="none" stroke={v(cssVar)} strokeOpacity={0.28} strokeWidth={10} strokeLinecap="round" />
        ))}
        {s > 0.5 && <path d={arc(100, 100, 78, 0.8, Math.max(1.2, s))} fill="none" stroke={color} strokeWidth={10} strokeLinecap="round" />}
        <circle cx={nx} cy={ny} r={7} fill="var(--surface)" stroke={color} strokeWidth={3.5} />
        <text x="100" y="102" textAnchor="middle" className="tabular" fill="var(--fg)" fontSize="44" fontWeight="650" letterSpacing="-1.5">{s}</text>
        <text x="100" y="126" textAnchor="middle" fill={color} fontSize="14" fontWeight="600">{t.enums.level[level]}</text>
        <text x="30" y="156" textAnchor="middle" fill="var(--fg-3)" fontSize="12">0</text>
        <text x="170" y="156" textAnchor="middle" fill="var(--fg-3)" fontSize="12">100</text>
      </svg>
    </div>
  );
}
