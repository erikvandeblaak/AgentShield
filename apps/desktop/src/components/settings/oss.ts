import type { Dict } from "../../i18n";

type UseKey = Extract<keyof Dict["about"], `use${string}`>;

export interface OssComponent { name: string; license: string; use: UseKey }

/** Open-source components bundled with (or used to build) the dashboard. */
export const OSS_COMPONENTS: OssComponent[] = [
  { name: "react · react-dom", license: "MIT", use: "useUi" },
  { name: "zustand", license: "MIT", use: "useState" },
  { name: "@tanstack/react-table", license: "MIT", use: "useTable" },
  { name: "@tanstack/react-virtual", license: "MIT", use: "useVirtual" },
  { name: "echarts", license: "Apache-2.0", use: "useCharts" },
  { name: "codemirror · @codemirror/*", license: "MIT", use: "useEditor" },
  { name: "lucide-react", license: "ISC", use: "useIcons" },
  { name: "tailwindcss", license: "MIT", use: "useStyling" },
  { name: "@tauri-apps/api", license: "Apache-2.0 OR MIT", use: "useBridge" },
  { name: "Geist (Fontsource)", license: "OFL-1.1", use: "useFontUi" },
  { name: "JetBrains Mono (Fontsource)", license: "OFL-1.1", use: "useFontMono" },
  { name: "vite", license: "MIT", use: "useBuild" },
  { name: "typescript", license: "Apache-2.0", use: "useLang" },
];
