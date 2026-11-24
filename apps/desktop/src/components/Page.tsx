import type { ReactNode } from "react";
import { cx } from "./ui";

/**
 * Page container. Default: scrolling page with comfortable gutters.
 * `fill`: the page owns the full height (e.g. Live Activity's virtualised table) and manages its own scrolling.
 */
export function Page({ children, fill, className }: { children: ReactNode; fill?: boolean; className?: string }) {
  if (fill) return <div className={cx("flex h-full min-h-0 animate-fade-in flex-col px-8 pt-7 pb-6", className)}>{children}</div>;
  return (
    <div className="h-full overflow-y-auto">
      <div className={cx("mx-auto w-full max-w-[1720px] animate-fade-in px-8 pt-7 pb-12", className)}>{children}</div>
    </div>
  );
}
