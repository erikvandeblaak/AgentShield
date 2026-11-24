//! Session correlation: combines the current event with recent events of the same session.
//!
//! Correlation is **not** proof of causality. Correlated findings carry `Low`/`Medium`
//! confidence and say so in their explanation. They raise the risk score so that policies
//! can react (e.g. ask before a network call that follows a credential read).

use agentshield_event_model::{
    AuditRecord, Confidence, Finding, NormalizedEvent, Phase, RiskAssessment, RiskCategory,
};

fn is_egress(ev: &NormalizedEvent, risk: &RiskAssessment) -> bool {
    use agentshield_event_model::ActionKind as A;
    matches!(ev.action, A::NetworkFetch { .. } | A::WebSearch { .. })
        || risk.categories.iter().any(|c| {
            matches!(
                c,
                RiskCategory::DataExfiltration | RiskCategory::UnsafeNetworkAccess
            )
        })
        || risk
            .findings
            .iter()
            .any(|f| f.id.starts_with("network.") || f.id == "mcp.egress_capability")
}

fn within(ts: &str, window_minutes: u32) -> bool {
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(t) => {
            chrono::Utc::now().signed_duration_since(t)
                <= chrono::Duration::minutes(i64::from(window_minutes))
        }
        Err(_) => false,
    }
}

/// Correlation findings for `ev` given `recent` records (newest first) of the same session.
pub fn correlate(
    ev: &NormalizedEvent,
    risk: &RiskAssessment,
    recent: &[AuditRecord],
    window_minutes: u32,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if ev.phase != Phase::Pre || recent.is_empty() {
        return out;
    }
    let recent: Vec<&AuditRecord> = recent
        .iter()
        .filter(|r| within(&r.ts_utc, window_minutes) && r.session_id == ev.ctx.session_id)
        .collect();

    // 1. Credential access followed by egress.
    if is_egress(ev, risk)
        && let Some(prev) = recent.iter().find(|r| {
            r.risk.score >= 60
                && r.risk.categories.iter().any(|c| {
                    matches!(
                        c,
                        RiskCategory::SecretAccess | RiskCategory::CredentialExposure
                    )
                })
        })
    {
        out.push(Finding {
                id: "correlation.secret_then_egress".into(),
                category: RiskCategory::DataExfiltration,
                score: 80,
                confidence: Confidence::Low,
                explanation: format!(
                    "Network activity in the same session shortly after credential access (event #{}: {}). Correlation only — not proof that data was sent.",
                    prev.id, prev.summary
                ),
                evidence: Some(format!("event #{}", prev.id)),
                mitigation: Some("Review what the agent read and where it is connecting to.".into()),
            });
    }
    // 2. Risky action after untrusted content with prompt-injection indicators.
    if risk.score >= 40
        && let Some(prev) = recent.iter().find(|r| {
            r.risk
                .categories
                .contains(&RiskCategory::PromptInjectionIndicator)
        })
    {
        out.push(Finding {
                id: "correlation.injection_then_risky_action".into(),
                category: RiskCategory::PromptInjectionIndicator,
                score: 75,
                confidence: Confidence::Low,
                explanation: format!(
                    "Risky action shortly after the agent received content with prompt-injection indicators (event #{}). Correlation only.",
                    prev.id
                ),
                evidence: Some(format!("event #{}", prev.id)),
                mitigation: Some("Check whether the instruction came from you or from fetched content.".into()),
            });
    }
    // 3. Repeated attempts at blocked/denied actions.
    let denied = recent
        .iter()
        .filter(|r| {
            r.phase == Phase::Pre
                && r.simulated_decision.rank()
                    >= agentshield_event_model::PolicyDecision::Deny.rank()
        })
        .count();
    if denied >= 3 && risk.score >= 40 {
        out.push(Finding {
            id: "correlation.repeated_denied_attempts".into(),
            category: risk.categories.first().copied().unwrap_or(RiskCategory::DestructiveOperation),
            score: 70,
            confidence: Confidence::Medium,
            explanation: format!("{denied} actions in this session were already rated 'deny' within the correlation window; the agent keeps attempting risky actions."),
            evidence: None,
            mitigation: Some("Consider pausing the session or switching to Interactive mode.".into()),
        });
    }
    out
}
