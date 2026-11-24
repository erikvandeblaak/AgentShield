import { beforeEach, describe, expect, it } from "vitest";
import { applyObserved, mergeLive, useLive } from "./live";
import type { EventRow, Outcome, Phase } from "../lib/types";

function row(id: number, phase: Phase = "pre", correlation: string | null = null, outcome: Outcome = "pending"): EventRow {
  return {
    record: {
      id, uuid: `u${id}`, schema_version: 1, ts_utc: new Date(Date.UTC(2026, 1, 14) + id * 1000).toISOString(), agent: "claude-code",
      agent_version: null, session_id: "s", workspace: "/w", hook_event: phase === "post" ? "PostToolUse" : "PreToolUse", phase,
      action_type: "shell.exec", tool: "Bash", summary: `cmd ${id}`, action: { type: "shell_exec", command: `cmd ${id}`, shell: "bash" },
      input_redacted: {}, risk: { score: 0, level: "informational", confidence: "high", categories: [], findings: [], explanation: [], uncertainties: [] },
      policy_version: "1", policy_name: "p", matched_rules: [], mode: "monitor", simulated_decision: "allow", decision_reason: null,
      actual_decision: phase === "pre" ? "no_opinion" : "not_applicable", outcome, coverage: "enforceable", latency_us: 1,
      correlation_id: correlation, via_daemon: true, prev_hash: "", hash: "",
    },
    observed_outcome: null,
  };
}

const ids = (rows: EventRow[]) => rows.map((r) => r.record.id);

describe("mergeLive", () => {
  it("prepends new rows newest first", () => {
    expect(ids(mergeLive([row(2), row(1)], [row(3), row(4)]))).toEqual([4, 3, 2, 1]);
  });
  it("drops duplicates, also within one batch", () => {
    const existing = [row(2), row(1)];
    expect(mergeLive(existing, [row(2), row(1)])).toBe(existing);
    expect(ids(mergeLive(existing, [row(3), row(3), row(2)]))).toEqual([3, 2, 1]);
  });
  it("caps the ring buffer and keeps the newest rows", () => {
    const merged = mergeLive([row(3), row(2), row(1)], [row(4), row(5)], 4);
    expect(ids(merged)).toEqual([5, 4, 3, 2]);
  });
  it("patches the observed outcome of the matching pre event when its post event arrives", () => {
    const merged = mergeLive([row(1, "pre", "c1")], [row(2, "post", "c1", "failed")]);
    expect(ids(merged)).toEqual([2, 1]);
    expect(merged[1]?.observed_outcome).toBe("failed");
    expect(merged[0]?.observed_outcome).toBeNull();
  });
});

describe("applyObserved", () => {
  it("ignores pre events, uncorrelated posts and unknown correlations", () => {
    const rows = [row(1, "pre", "c1")];
    expect(applyObserved(rows, row(2, "pre", "c1"))).toBe(rows);
    expect(applyObserved(rows, row(2, "post", null, "executed"))).toBe(rows);
    expect(applyObserved(rows, row(2, "post", "other", "executed"))).toBe(rows);
  });
  it("returns a new array without mutating the old rows", () => {
    const rows = [row(1, "pre", "c1")];
    const next = applyObserved(rows, row(2, "post", "c1", "executed"));
    expect(next).not.toBe(rows);
    expect(rows[0]?.observed_outcome).toBeNull();
    expect(next[0]?.observed_outcome).toBe("executed");
    expect(applyObserved(next, row(2, "post", "c1", "executed"))).toBe(next);
  });
});

describe("useLive store", () => {
  beforeEach(() => useLive.getState().clear());

  it("seeds, pushes and counts received rows", () => {
    useLive.getState().seed([row(2), row(1)]);
    useLive.getState().push([row(3)]);
    expect(ids(useLive.getState().rows)).toEqual([3, 2, 1]);
    expect(useLive.getState().received).toBe(1);
  });
  it("appends only strictly older rows", () => {
    useLive.getState().seed([row(10), row(9)]);
    useLive.getState().appendOlder([row(9), row(8), row(7)]);
    expect(ids(useLive.getState().rows)).toEqual([10, 9, 8, 7]);
  });
});
