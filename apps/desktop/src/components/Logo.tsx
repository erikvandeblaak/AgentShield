import { useId } from "react";
import { cx } from "./ui";

const SHIELD = "M32 3.5 55.5 11.6V29.8C55.5 44.9 45.9 55.6 32 60.5 18.1 55.6 8.5 44.9 8.5 29.8V11.6Z";

/** Original AgentShield mark: a geometric shield holding a scanning lens, grounded by one circuit trace. */
export function LogoMark({ size = 32, mono, className, scanning }: { size?: number; mono?: boolean; className?: string; scanning?: boolean }) {
  const id = useId();
  const ink = mono ? "currentColor" : "#07111F";
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} className={className} role="img" aria-label="Erik's AgentShield">
      {!mono && (
        <defs>
          <linearGradient id={id} x1="10" y1="6" x2="54" y2="58" gradientUnits="userSpaceOnUse">
            <stop stopColor="#34D399" />
            <stop offset=".55" stopColor="#22D3EE" />
            <stop offset="1" stopColor="#8B7CF6" />
          </linearGradient>
        </defs>
      )}
      <path d={SHIELD} fill={mono ? "none" : `url(#${id})`} stroke={mono ? "currentColor" : "none"} strokeWidth={mono ? 3.5 : 0} strokeLinejoin="round" />
      <path d="M17 29.5Q32 13.5 47 29.5 32 45.5 17 29.5Z" fill="none" stroke={ink} strokeWidth="3" strokeLinejoin="round" />
      <circle cx="32" cy="29.5" r="5.2" fill={ink} />
      <path d="M32 41.5V50" stroke={ink} strokeWidth="3" strokeLinecap="round" />
      <circle cx="32" cy="52" r="2.4" fill={ink} />
      {scanning && <path d="M19 29.5H45" stroke={ink} strokeWidth="1.6" strokeLinecap="round" opacity=".7" style={{ animation: "scan 1.8s ease-in-out infinite" }} />}
    </svg>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cx("whitespace-nowrap text-xl leading-none tracking-tight text-fg", className)}>
      <span className="font-normal text-fg-2">Erik&apos;s </span>
      <span className="font-semibold">Agent</span>
      <span className="font-normal text-fg-2">Shield</span>
    </span>
  );
}
