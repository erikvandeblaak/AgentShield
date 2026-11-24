import { beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ActualBadge, DecisionBadge, ModeBadge, RiskPill } from "./badges";
import { en } from "../i18n/en";
import { nl } from "../i18n/nl";
import { useApp } from "../store/app";
import { LEVEL_VAR, MODE_VAR } from "../theme/palette";
import type { Mode, RiskLevel } from "../lib/types";

const MODES: Mode[] = ["monitor", "shadow", "interactive", "enforce", "lockdown"];

beforeEach(() => useApp.setState({ language: "en" }));

describe("ModeBadge", () => {
  it.each(MODES)("renders %s with its label, data-mode and mode colour", (mode) => {
    const { container } = render(<ModeBadge mode={mode} />);
    const label = screen.getByText(en.enums.mode[mode].label);
    expect(label).toHaveAttribute("data-mode", mode);
    const toned = container.querySelector<HTMLElement>(".tone");
    expect(toned?.style.getPropertyValue("--tone")).toBe(`var(${MODE_VAR[mode]})`);
  });

  it.each(MODES)("large %s shows the banner text", (mode) => {
    const { container } = render(<ModeBadge mode={mode} size="lg" showTagline />);
    expect(screen.getByText(en.enums.mode[mode].banner)).toBeInTheDocument();
    const el = container.querySelector<HTMLElement>(`[data-mode="${mode}"]`);
    expect(el?.style.getPropertyValue("--tone")).toBe(`var(${MODE_VAR[mode]})`);
    expect(container.textContent).toContain(en.enums.mode[mode].tagline);
  });

  it("uses the spec colour language and wording", () => {
    expect(MODE_VAR).toEqual({
      monitor: "--mode-monitor", shadow: "--mode-shadow", interactive: "--mode-interactive", enforce: "--mode-enforce", lockdown: "--mode-lockdown",
    });
    expect(en.enums.mode.monitor.banner).toBe("MONITOR MODE");
    expect(en.enums.mode.monitor.tagline).toBe("Observing, not blocking");
  });

  it("follows the configured language", () => {
    useApp.setState({ language: "nl" });
    render(<ModeBadge mode="interactive" />);
    expect(screen.getByText(nl.enums.mode.interactive.label)).toBeInTheDocument();
  });
});

describe("RiskPill", () => {
  const cases: [number, RiskLevel][] = [
    [0, "informational"], [19, "informational"], [20, "low"], [39, "low"], [40, "medium"], [59, "medium"],
    [60, "high"], [79, "high"], [80, "critical"], [100, "critical"],
  ];
  it.each(cases)("score %i is in the %s band", (score, level) => {
    render(<RiskPill score={score} />);
    const pill = screen.getByText(String(score));
    expect(pill).toHaveAttribute("data-level", level);
    expect(pill.style.getPropertyValue("--tone")).toBe(`var(${LEVEL_VAR[level]})`);
    expect(pill.title).toContain(en.enums.level[level]);
  });

  it("can show the level label", () => {
    render(<RiskPill score={85} showLabel />);
    expect(screen.getByText(en.enums.level.critical)).toBeInTheDocument();
  });
});

describe("decision badges", () => {
  it("words unenforced policy results as 'would …'", () => {
    render(<DecisionBadge decision="deny" simulated />);
    expect(screen.getByText(en.enums.would.deny)).toBeInTheDocument();
  });
  it("words enforced results plainly", () => {
    render(<DecisionBadge decision="deny" />);
    expect(screen.getByText(en.enums.decision.deny)).toBeInTheDocument();
  });
  it("shows what AgentShield actually did", () => {
    render(<><ActualBadge decision="deny" /><ActualBadge decision="no_opinion" /></>);
    expect(screen.getByText(en.enums.actual.deny)).toBeInTheDocument();
    expect(screen.getByText(en.enums.actual.no_opinion)).toBeInTheDocument();
  });
});
