use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::StreamExt;
use provider_core::{
    ProviderKind, ProviderQuotaError, ProviderQuotaErrorKind, ProviderQuotaSnapshot, QuotaAmount,
    QuotaGroup, QuotaGroupAudience, QuotaGroupScope, QuotaMetric, QuotaMetricKind, QuotaPeriod,
    QuotaPeriodKind, QuotaScalar, QuotaUnit,
};
use serde::Deserialize;

use super::{
    credentials::CodexCredentials,
    identity::{DEFAULT_BACKEND_ROOT, quota_headers},
};

const MAX_RESPONSE_SIZE: usize = 64 * 1024;
const QUOTA_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub(crate) struct CodexQuotaClient {
    http: reqwest::Client,
    backend_root: String,
}

impl CodexQuotaClient {
    pub(crate) fn new() -> Self {
        Self::with_backend_root(DEFAULT_BACKEND_ROOT)
    }

    pub(crate) fn with_backend_root(backend_root: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(QUOTA_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            backend_root: backend_root.trim_end_matches('/').to_owned(),
        }
    }

    pub(crate) async fn fetch(
        &self,
        account_id: &str,
        credentials: &CodexCredentials,
    ) -> Result<ProviderQuotaSnapshot, ProviderQuotaError> {
        let request = self.http.get(format!("{}/wham/usage", self.backend_root));
        let request = quota_headers(request, credentials).map_err(provider_error)?;
        let response = request
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| upstream_error("Codex quota request failed"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error("Codex quota", status));
        }
        let body = read_limited(response, "Codex quota").await?;
        let payload: UsagePayload = serde_json::from_slice(&body).map_err(|_| {
            ProviderQuotaError::new(
                ProviderQuotaErrorKind::InvalidResponse,
                "Codex quota returned invalid JSON",
            )
        })?;
        normalize_usage(account_id, payload)
    }
}

pub(crate) fn normalize_headers(headers: &reqwest::header::HeaderMap) -> Vec<QuotaGroup> {
    let mut groups = Vec::new();
    if let Some(group) = header_limit_group(headers, "codex", None) {
        groups.push(group);
    }

    let mut limit_ids = std::collections::BTreeSet::new();
    for name in headers.keys() {
        let name = name.as_str().to_ascii_lowercase();
        let Some(prefix) = name.strip_suffix("-primary-used-percent") else {
            continue;
        };
        let Some(limit_id) = prefix.strip_prefix("x-") else {
            continue;
        };
        if limit_id != "codex" {
            limit_ids.insert(limit_id.to_owned());
        }
    }
    for limit_id in limit_ids {
        let limit_name = header_string(headers, &format!("x-{limit_id}-limit-name"));
        if let Some(group) = header_limit_group(headers, &limit_id, limit_name.as_deref()) {
            groups.push(group);
        }
    }

    let has_credits = header_bool(headers, "x-codex-credits-has-credits");
    let unlimited = header_bool(headers, "x-codex-credits-unlimited");
    let balance = header_string(headers, "x-codex-credits-balance");
    if has_credits.is_some() || unlimited.is_some() || balance.is_some() {
        groups.push(owner_group(
            None,
            has_credits,
            unlimited,
            balance,
            None,
            None,
            None,
        ));
    }
    groups
}

fn normalize_usage(
    account_id: &str,
    payload: UsagePayload,
) -> Result<ProviderQuotaSnapshot, ProviderQuotaError> {
    let mut groups = Vec::new();
    if let Some(rate_limit) = payload.rate_limit {
        groups.push(rate_limit_group(
            "codex",
            None,
            rate_limit,
            QuotaGroupScope::Aggregate,
        ));
    }
    for additional in payload.additional_rate_limits.unwrap_or_default() {
        let id = normalized_key(&additional.metered_feature);
        if id.is_empty() {
            continue;
        }
        if let Some(rate_limit) = additional.rate_limit {
            groups.push(rate_limit_group(
                &id,
                non_empty(additional.limit_name).as_deref(),
                rate_limit,
                QuotaGroupScope::Product,
            ));
        }
    }

    let reached_type = payload
        .rate_limit_reached_type
        .and_then(|value| match value {
            ReachedType::Text(value) => non_empty(value),
            ReachedType::Object { kind } => non_empty(kind),
        });
    let reset_count = payload
        .rate_limit_reset_credits
        .map(|credits| credits.available_count);
    let credits = payload.credits.unwrap_or_default();
    groups.push(owner_group(
        non_empty(payload.plan_type),
        credits.has_credits,
        credits.unlimited,
        credits.balance.and_then(non_empty),
        payload.spend_control,
        reached_type,
        reset_count,
    ));
    groups.retain(|group| !group.metrics.is_empty() || !group.attributes.is_empty());
    if groups.is_empty() {
        return Err(ProviderQuotaError::new(
            ProviderQuotaErrorKind::InvalidResponse,
            "Codex quota did not contain supported fields",
        ));
    }

    Ok(ProviderQuotaSnapshot {
        account_id: account_id.to_owned(),
        provider: ProviderKind::Codex,
        fetched_at: unix_timestamp(),
        last_observed_at: None,
        groups,
        warnings: Vec::new(),
    })
}

fn rate_limit_group(
    id: &str,
    limit_name: Option<&str>,
    status: RateLimitStatus,
    scope: QuotaGroupScope,
) -> QuotaGroup {
    let mut attributes = BTreeMap::new();
    if let Some(allowed) = status.allowed {
        attributes.insert("allowed".to_owned(), QuotaScalar::Bool(allowed));
    }
    if let Some(limit_reached) = status.limit_reached {
        attributes.insert("limit_reached".to_owned(), QuotaScalar::Bool(limit_reached));
    }
    if let Some(limit_name) = limit_name.and_then(|value| non_empty(value.to_owned())) {
        attributes.insert("limit_name".to_owned(), QuotaScalar::Text(limit_name));
    }
    let mut metrics = Vec::new();
    if let Some(window) = status.primary_window {
        metrics.push(window_metric("primary", window));
    }
    if let Some(window) = status.secondary_window {
        metrics.push(window_metric("secondary", window));
    }
    QuotaGroup {
        key: group_key(id),
        scope,
        audience: QuotaGroupAudience::Shared,
        attributes,
        metrics,
    }
}

fn header_limit_group(
    headers: &reqwest::header::HeaderMap,
    id: &str,
    limit_name: Option<&str>,
) -> Option<QuotaGroup> {
    let prefix = format!("x-{id}");
    let primary = header_window(headers, &prefix, "primary");
    let secondary = header_window(headers, &prefix, "secondary");
    if primary.is_none() && secondary.is_none() {
        return None;
    }
    Some(rate_limit_group(
        id,
        limit_name,
        RateLimitStatus {
            allowed: None,
            limit_reached: None,
            primary_window: primary,
            secondary_window: secondary,
        },
        if id == "codex" {
            QuotaGroupScope::Aggregate
        } else {
            QuotaGroupScope::Product
        },
    ))
}

fn header_window(
    headers: &reqwest::header::HeaderMap,
    prefix: &str,
    name: &str,
) -> Option<RateLimitWindow> {
    let used_percent = header_f64(headers, &format!("{prefix}-{name}-used-percent"))?;
    let duration_seconds = header_i64(headers, &format!("{prefix}-{name}-window-minutes"))
        .and_then(|minutes| minutes.checked_mul(60));
    let reset_at = header_i64(headers, &format!("{prefix}-{name}-reset-at"));
    if used_percent == 0.0 && duration_seconds.is_none() && reset_at.is_none() {
        return None;
    }
    Some(RateLimitWindow {
        used_percent,
        limit_window_seconds: duration_seconds,
        reset_at,
    })
}

fn window_metric(key: &str, window: RateLimitWindow) -> QuotaMetric {
    let used = window.used_percent.clamp(0.0, 100.0);
    QuotaMetric {
        key: key.to_owned(),
        kind: QuotaMetricKind::Usage,
        unit: QuotaUnit::Percent,
        used: Some(QuotaAmount::Decimal(used)),
        remaining: Some(QuotaAmount::Decimal((100.0 - used).max(0.0))),
        limit: Some(QuotaAmount::Decimal(100.0)),
        period: Some(QuotaPeriod {
            kind: QuotaPeriodKind::Rolling,
            starts_at: None,
            ends_at: window.reset_at,
            duration_seconds: window.limit_window_seconds,
        }),
        breakdown: Vec::new(),
    }
}

fn owner_group(
    plan_type: Option<String>,
    has_credits: Option<bool>,
    unlimited: Option<bool>,
    balance: Option<String>,
    spend_control: Option<SpendControl>,
    reached_type: Option<String>,
    reset_count: Option<i64>,
) -> QuotaGroup {
    let mut attributes = BTreeMap::new();
    if let Some(plan_type) = plan_type {
        attributes.insert("plan_type".to_owned(), QuotaScalar::Text(plan_type));
    }
    if let Some(has_credits) = has_credits {
        attributes.insert("has_credits".to_owned(), QuotaScalar::Bool(has_credits));
    }
    if let Some(unlimited) = unlimited {
        attributes.insert("unlimited".to_owned(), QuotaScalar::Bool(unlimited));
    }
    if let Some(reached_type) = reached_type {
        attributes.insert(
            "rate_limit_reached_type".to_owned(),
            QuotaScalar::Text(reached_type),
        );
    }

    let mut metrics = Vec::new();
    if let Some(balance) = balance {
        metrics.push(QuotaMetric {
            key: "credits".to_owned(),
            kind: QuotaMetricKind::Balance,
            unit: QuotaUnit::Credits,
            used: None,
            remaining: Some(QuotaAmount::DecimalString(balance)),
            limit: None,
            period: None,
            breakdown: Vec::new(),
        });
    }
    if let Some(spend_control) = spend_control {
        attributes.insert(
            "spend_control_reached".to_owned(),
            QuotaScalar::Bool(spend_control.reached),
        );
        if let Some(limit) = spend_control.individual_limit {
            attributes.insert(
                "spend_limit".to_owned(),
                QuotaScalar::DecimalString(limit.limit),
            );
            attributes.insert(
                "spend_used".to_owned(),
                QuotaScalar::DecimalString(limit.used),
            );
            attributes.insert(
                "spend_remaining".to_owned(),
                QuotaScalar::DecimalString(limit.remaining),
            );
            attributes.insert(
                "spend_remaining_percent".to_owned(),
                QuotaScalar::Integer(i64::from(limit.remaining_percent)),
            );
            attributes.insert(
                "spend_resets_at".to_owned(),
                QuotaScalar::Integer(limit.reset_at),
            );
        }
    }
    if let Some(reset_count) = reset_count {
        metrics.push(QuotaMetric {
            key: "reset_credits".to_owned(),
            kind: QuotaMetricKind::Balance,
            unit: QuotaUnit::Count,
            used: None,
            remaining: Some(QuotaAmount::Integer(reset_count)),
            limit: None,
            period: None,
            breakdown: Vec::new(),
        });
    }
    QuotaGroup {
        key: "account".to_owned(),
        scope: QuotaGroupScope::Billing,
        audience: QuotaGroupAudience::OwnerOnly,
        attributes,
        metrics,
    }
}

async fn read_limited(
    response: reqwest::Response,
    operation: &str,
) -> Result<Vec<u8>, ProviderQuotaError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| upstream_error(format!("failed to read {operation} response")))?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_SIZE {
            return Err(ProviderQuotaError::new(
                ProviderQuotaErrorKind::InvalidResponse,
                format!("{operation} response was too large"),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn status_error(operation: &str, status: reqwest::StatusCode) -> ProviderQuotaError {
    let kind = match status.as_u16() {
        401 | 403 => ProviderQuotaErrorKind::Authentication,
        429 => ProviderQuotaErrorKind::RateLimited,
        _ => ProviderQuotaErrorKind::Upstream,
    };
    ProviderQuotaError::new(kind, format!("{operation} returned HTTP {status}"))
        .with_upstream_status(status.as_u16())
}

fn provider_error(error: provider_core::ProviderError) -> ProviderQuotaError {
    let kind = match error.kind() {
        provider_core::ProviderErrorKind::Authentication => ProviderQuotaErrorKind::Authentication,
        provider_core::ProviderErrorKind::RateLimited => ProviderQuotaErrorKind::RateLimited,
        provider_core::ProviderErrorKind::InvalidRequest => ProviderQuotaErrorKind::InvalidResponse,
        provider_core::ProviderErrorKind::Upstream => ProviderQuotaErrorKind::Upstream,
        provider_core::ProviderErrorKind::Internal => ProviderQuotaErrorKind::Internal,
    };
    ProviderQuotaError::new(kind, error.message())
}

fn upstream_error(message: impl Into<String>) -> ProviderQuotaError {
    ProviderQuotaError::new(ProviderQuotaErrorKind::Upstream, message)
}

fn group_key(id: &str) -> String {
    let id = normalized_key(id);
    if id == "codex" {
        "codex".to_owned()
    } else {
        format!("limit_{id}")
    }
}

fn normalized_key(value: &str) -> String {
    let mut normalized = String::new();
    let mut previous_underscore = false;
    for character in value.trim().chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() {
            normalized.push(character);
            previous_underscore = false;
        } else if !previous_underscore && !normalized.is_empty() {
            normalized.push('_');
            previous_underscore = true;
        }
    }
    normalized.trim_end_matches('_').to_owned()
}

fn header_string(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn header_f64(headers: &reqwest::header::HeaderMap, name: &str) -> Option<f64> {
    header_string(headers, name)?
        .parse()
        .ok()
        .filter(|value: &f64| value.is_finite())
}

fn header_i64(headers: &reqwest::header::HeaderMap, name: &str) -> Option<i64> {
    header_string(headers, name)?.parse().ok()
}

fn header_bool(headers: &reqwest::header::HeaderMap, name: &str) -> Option<bool> {
    let value = header_string(headers, name)?;
    if value.eq_ignore_ascii_case("true") || value == "1" {
        Some(true)
    } else if value.eq_ignore_ascii_case("false") || value == "0" {
        Some(false)
    } else {
        None
    }
}

fn non_empty(value: String) -> Option<String> {
    let value = value.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[derive(Default, Deserialize)]
struct UsagePayload {
    #[serde(default)]
    plan_type: String,
    rate_limit: Option<RateLimitStatus>,
    credits: Option<CreditStatus>,
    spend_control: Option<SpendControl>,
    additional_rate_limits: Option<Vec<AdditionalRateLimit>>,
    rate_limit_reached_type: Option<ReachedType>,
    rate_limit_reset_credits: Option<ResetCredits>,
}

#[derive(Deserialize)]
struct RateLimitStatus {
    allowed: Option<bool>,
    limit_reached: Option<bool>,
    primary_window: Option<RateLimitWindow>,
    secondary_window: Option<RateLimitWindow>,
}

#[derive(Deserialize)]
struct RateLimitWindow {
    used_percent: f64,
    #[serde(default)]
    limit_window_seconds: Option<i64>,
    #[serde(default)]
    reset_at: Option<i64>,
}

#[derive(Default, Deserialize)]
struct CreditStatus {
    has_credits: Option<bool>,
    unlimited: Option<bool>,
    balance: Option<String>,
}

#[derive(Deserialize)]
struct SpendControl {
    reached: bool,
    individual_limit: Option<SpendLimit>,
}

#[derive(Deserialize)]
struct SpendLimit {
    limit: String,
    used: String,
    remaining: String,
    remaining_percent: i32,
    reset_at: i64,
}

#[derive(Deserialize)]
struct AdditionalRateLimit {
    #[serde(default)]
    limit_name: String,
    #[serde(default)]
    metered_feature: String,
    rate_limit: Option<RateLimitStatus>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReachedType {
    Text(String),
    Object {
        #[serde(rename = "type")]
        kind: String,
    },
}

#[derive(Deserialize)]
struct ResetCredits {
    available_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_wham_usage_with_shared_and_owner_only_groups() {
        let payload: UsagePayload = serde_json::from_value(serde_json::json!({
            "plan_type": "pro",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": {
                    "used_percent": 42,
                    "limit_window_seconds": 300,
                    "reset_after_seconds": 10,
                    "reset_at": 123
                },
                "secondary_window": {
                    "used_percent": 84,
                    "limit_window_seconds": 3600,
                    "reset_at": 456
                }
            },
            "credits": {
                "has_credits": true,
                "unlimited": false,
                "balance": "9.99",
                "approx_local_messages": [{"ignored": true}]
            },
            "spend_control": {
                "reached": false,
                "individual_limit": {
                    "limit": "25000",
                    "used": "8000",
                    "remaining": "17000",
                    "remaining_percent": 68,
                    "reset_at": 789
                }
            },
            "additional_rate_limits": [{
                "limit_name": "Sonic",
                "metered_feature": "codex_other",
                "rate_limit": {
                    "allowed": true,
                    "limit_reached": false,
                    "primary_window": {
                        "used_percent": 70,
                        "limit_window_seconds": 900,
                        "reset_at": 900
                    }
                }
            }],
            "rate_limit_reached_type": {
                "type": "workspace_member_credits_depleted"
            },
            "rate_limit_reset_credits": {"available_count": 3}
        }))
        .expect("WHAM payload");

        let snapshot = normalize_usage("account-1", payload).expect("quota snapshot");
        let codex = group(&snapshot.groups, "codex");
        assert_eq!(codex.audience, QuotaGroupAudience::Shared);
        assert_eq!(codex.metrics.len(), 2);
        assert_eq!(codex.metrics[0].unit, QuotaUnit::Percent);
        assert_eq!(
            codex.metrics[0]
                .period
                .as_ref()
                .and_then(|period| period.duration_seconds),
            Some(300)
        );
        assert_eq!(
            codex.metrics[0]
                .period
                .as_ref()
                .and_then(|period| period.ends_at),
            Some(123)
        );

        let additional = group(&snapshot.groups, "limit_codex_other");
        assert_eq!(additional.audience, QuotaGroupAudience::Shared);
        assert_eq!(
            additional.attributes.get("limit_name"),
            Some(&QuotaScalar::Text("Sonic".to_owned()))
        );

        let account = group(&snapshot.groups, "account");
        assert_eq!(account.audience, QuotaGroupAudience::OwnerOnly);
        assert_eq!(
            account.attributes.get("plan_type"),
            Some(&QuotaScalar::Text("pro".to_owned()))
        );
        assert_eq!(
            account.attributes.get("spend_limit"),
            Some(&QuotaScalar::DecimalString("25000".to_owned()))
        );
        assert_eq!(
            account.metrics[0].remaining,
            Some(QuotaAmount::DecimalString("9.99".to_owned()))
        );
        assert_eq!(account.metrics[1].remaining, Some(QuotaAmount::Integer(3)));
    }

    #[test]
    fn parses_all_header_families_and_keeps_credits_owner_only() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-codex-primary-used-percent",
            "12.5".parse().expect("header"),
        );
        headers.insert(
            "x-codex-primary-window-minutes",
            "60".parse().expect("header"),
        );
        headers.insert(
            "x-codex-primary-reset-at",
            "1704069000".parse().expect("header"),
        );
        headers.insert(
            "x-codex-other-primary-used-percent",
            "80".parse().expect("header"),
        );
        headers.insert("x-codex-other-limit-name", "Sonic".parse().expect("header"));
        headers.insert(
            "x-codex-credits-has-credits",
            "TRUE".parse().expect("header"),
        );
        headers.insert(
            "x-codex-credits-unlimited",
            "false".parse().expect("header"),
        );
        headers.insert("x-codex-credits-balance", "1.25".parse().expect("header"));

        let groups = normalize_headers(&headers);
        assert_eq!(group(&groups, "codex").audience, QuotaGroupAudience::Shared);
        assert_eq!(
            group(&groups, "limit_codex_other").audience,
            QuotaGroupAudience::Shared
        );
        assert_eq!(
            group(&groups, "account").audience,
            QuotaGroupAudience::OwnerOnly
        );
    }

    fn group<'a>(groups: &'a [QuotaGroup], key: &str) -> &'a QuotaGroup {
        groups
            .iter()
            .find(|group| group.key == key)
            .expect("quota group")
    }
}
