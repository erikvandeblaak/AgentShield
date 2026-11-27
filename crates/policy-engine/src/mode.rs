//! Mode decision: turns a mode-independent [`PolicyOutcome`] into what AgentShield actually
//! tells the agent. This is the single place where blocking happens.
//!
//! Invariants (tested in `src/tests.rs`, `invariant_*` tests, and the end-to-end test):
//! * Monitor and Shadow never return Ask or Deny.
//! * No mode ever returns an explicit allow (AgentShield cannot weaken native permissions).
//! * Non-enforceable events (post-execution, lifecycle) are always NotApplicable.
//! * On hook events where the agent cannot ask the user (Claude Code `PreSkillShellCommand`
//!   treats `ask` as `deny`), Ask is recorded and sent as Deny, so the audit log says what
//!   really happens.

use crate::PolicyOutcome;
use agentshield_event_model::{
    ActionKind, ActualDecision, Mode, NormalizedEvent, Phase, PolicyDecision, RiskAssessment,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModeOutcome {
    pub actual: ActualDecision,
    /// Message for the agent / user (deny reason or ask prompt).
    pub message: Option<String>,
}

fn message(prefix: &str, outcome: &PolicyOutcome, risk: &RiskAssessment) -> String {
    let mut m = format!(
        "AgentShield {prefix}: {} (risk {} {}",
        outcome.reason,
        risk.score,
        risk.level.as_str()
    );
    if let Some(f) = risk.findings.first() {
        m.push_str(&format!("; {}", f.explanation));
    }
    m.push(')');
    if let Some(s) = &outcome.suggestion {
        m.push_str(&format!(". Safer alternative: {s}"));
    }
    m
}

/// Native hook events on which an `ask` answer is treated as `deny` by the agent.
const NO_ASK_HOOK_EVENTS: &[&str] = &["PreSkillShellCommand"];

/// Decide what to tell the agent.
pub fn apply_mode(
    mode: Mode,
    outcome: &PolicyOutcome,
    ev: &NormalizedEvent,
    risk: &RiskAssessment,
) -> ModeOutcome {
    let mo = decide(mode, outcome, ev, risk);
    if mo.actual == ActualDecision::Ask && NO_ASK_HOOK_EVENTS.contains(&ev.ctx.hook_event.as_str())
    {
        return ModeOutcome {
            actual: ActualDecision::Deny,
            message: mo.message.map(|m| {
                format!(
                    "{}. Claude Code cannot ask about shell commands that a skill runs while loading, so this is denied.",
                    m.replacen("asks for approval", "blocked (would ask for approval)", 1)
                )
            }),
        };
    }
    mo
}

fn decide(
    mode: Mode,
    outcome: &PolicyOutcome,
    ev: &NormalizedEvent,
    risk: &RiskAssessment,
) -> ModeOutcome {
    if ev.phase != Phase::Pre || !ev.enforceable {
        return ModeOutcome {
            actual: ActualDecision::NotApplicable,
            message: None,
        };
    }
    let d = outcome.decision;
    match mode {
        Mode::Monitor | Mode::Shadow => ModeOutcome {
            actual: ActualDecision::NoOpinion,
            message: None,
        },
        Mode::Interactive => {
            if outcome.hard {
                ModeOutcome {
                    actual: ActualDecision::Deny,
                    message: Some(message("blocked (hard rule)", outcome, risk)),
                }
            } else if matches!(
                d,
                PolicyDecision::Deny | PolicyDecision::Ask | PolicyDecision::RequireSandbox
            ) {
                ModeOutcome {
                    actual: ActualDecision::Ask,
                    message: Some(message("asks for approval", outcome, risk)),
                }
            } else {
                ModeOutcome {
                    actual: ActualDecision::NoOpinion,
                    message: None,
                }
            }
        }
        Mode::Enforce => match d {
            PolicyDecision::Deny => ModeOutcome {
                actual: ActualDecision::Deny,
                message: Some(message("blocked", outcome, risk)),
            },
            // No sandbox runtime is available on this surface: requiring one means denying.
            PolicyDecision::RequireSandbox => ModeOutcome {
                actual: ActualDecision::Deny,
                message: Some(message(
                    "blocked (sandbox required but no enforceable sandbox is available)",
                    outcome,
                    risk,
                )),
            },
            PolicyDecision::Ask => ModeOutcome {
                actual: ActualDecision::Ask,
                message: Some(message("asks for approval", outcome, risk)),
            },
            PolicyDecision::Warn | PolicyDecision::Allow => ModeOutcome {
                actual: ActualDecision::NoOpinion,
                message: None,
            },
        },
        Mode::Lockdown => {
            let reason = if d.rank() >= PolicyDecision::Ask.rank() {
                Some("policy decision is ask/deny")
            } else if ev.action.is_mutating() {
                Some("mutating actions are blocked during lockdown")
            } else if matches!(
                ev.action,
                ActionKind::NetworkFetch { .. } | ActionKind::WebSearch { .. }
            ) {
                Some("network access is blocked during lockdown")
            } else if risk.score >= 40 {
                Some("risky reads are blocked during lockdown")
            } else {
                None
            };
            match reason {
                Some(r) => ModeOutcome {
                    actual: ActualDecision::Deny,
                    message: Some(format!(
                        "AgentShield LOCKDOWN: {r}. Lockdown was activated by the user; ask them to return to a normal mode."
                    )),
                },
                None => ModeOutcome {
                    actual: ActualDecision::NoOpinion,
                    message: None,
                },
            }
        }
    }
}
