import {
  Activity, Bot, FileBarChart, FlaskConical, Globe, Info, KeyRound, LayoutDashboard, ListTree, Package, Plug, ScrollText,
  Settings, ShieldAlert, UserCheck, type LucideIcon,
} from "lucide-react";
import type { RouteId } from "../lib/router";

export interface NavItem { id: RouteId; icon: LucideIcon; key: string }
export interface NavGroup { label: "groupObserve" | "groupProtect" | "groupCenters" | "groupSystem"; items: NavItem[] }

/** `key` is the second key of the "g <key>" navigation chord. */
export const NAV: NavGroup[] = [
  {
    label: "groupObserve",
    items: [
      { id: "overview", icon: LayoutDashboard, key: "o" },
      { id: "live", icon: Activity, key: "l" },
      { id: "threats", icon: ShieldAlert, key: "t" },
      { id: "sessions", icon: ListTree, key: "s" },
    ],
  },
  {
    label: "groupProtect",
    items: [
      { id: "agents", icon: Bot, key: "a" },
      { id: "approvals", icon: UserCheck, key: "p" },
      { id: "policy", icon: ScrollText, key: "y" },
      { id: "simulator", icon: FlaskConical, key: "r" },
    ],
  },
  {
    label: "groupCenters",
    items: [
      { id: "secrets", icon: KeyRound, key: "k" },
      { id: "mcp", icon: Plug, key: "m" },
      { id: "supply-chain", icon: Package, key: "c" },
      { id: "network", icon: Globe, key: "n" },
    ],
  },
  {
    label: "groupSystem",
    items: [
      { id: "reports", icon: FileBarChart, key: "e" },
      { id: "settings", icon: Settings, key: "," },
      { id: "about", icon: Info, key: "i" },
    ],
  },
];

export const NAV_ITEMS: NavItem[] = NAV.flatMap((g) => g.items);
