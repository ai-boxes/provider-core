use std::time::{Duration, SystemTime, UNIX_EPOCH};

use provider_core::{
    BoundedBodyError, ProviderKind, ProviderQuotaError, ProviderQuotaErrorKind,
    ProviderQuotaSnapshot, QuotaAmount, QuotaBreakdown, QuotaGroup, QuotaGroupAudience,
    QuotaGroupScope, QuotaMetric, QuotaMetricKind, QuotaPeriod, QuotaPeriodKind, QuotaUnit,
    collect_bounded_body,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    credentials::GrokCredentials,
    identity::{DEFAULT_PROXY_BASE_URL, session_headers},
};

const MAX_RESPONSE_SIZE: usize = 64 * 1024;
const USER_TIMEOUT: Duration = Duration::from_secs(10);
const BILLING_TIMEOUT: Duration = Duration::from_secs(15);
const BILLING_TRANSPORT_ATTEMPTS: usize = 5;
const BILLING_RETRY_DELAY: Duration = Duration::from_millis(750);

#[derive(Clone)]
pub(crate) struct GrokQuotaClient {
    http: reqwest::Client,
    base_url: String,
}

impl GrokQuotaClient {
    pub(crate) fn new() -> Self {
        Self::with_base_url(DEFAULT_PROXY_BASE_URL)
    }

    pub(crate) async fn fetch_user_id(
        &self,
        credentials: &GrokCredentials,
    ) -> Result<String, ProviderQuotaError> {
        self.fetch_user_id_with_access_token(credentials.access_token().expose_secret())
            .await
    }

    pub(crate) async fn fetch_user_id_with_access_token(
        &self,
        access_token: &str,
    ) -> Result<String, ProviderQuotaError> {
        let response = session_headers(
            self.http
                .get(format!("{}/user", self.base_url))
                .bearer_auth(access_token),
        )
        .timeout(USER_TIMEOUT)
        .send()
        .await
        .map_err(|_| upstream_error("Grok user request failed"))?;
        let response: UserResponse = response_json(response, "Grok user").await?;
        let user_id = response.user_id.trim();
        if user_id.is_empty() {
            return Err(ProviderQuotaError::new(
                ProviderQuotaErrorKind::InvalidResponse,
                "Grok user response is missing userId",
            ));
        }
        Ok(user_id.to_owned())
    }

    pub(crate) async fn fetch_quota(
        &self,
        account_id: &str,
        credentials: &GrokCredentials,
        user_id: &str,
    ) -> Result<ProviderQuotaSnapshot, ProviderQuotaError> {
        let mut attempt = 1;
        let response = loop {
            match session_headers(
                self.http
                    .get(format!("{}/billing?format=credits", self.base_url))
                    .bearer_auth(credentials.access_token().expose_secret()),
            )
            .header("x-userid", user_id)
            .timeout(BILLING_TIMEOUT)
            .send()
            .await
            {
                Ok(received) => break received,
                Err(error) if attempt < BILLING_TRANSPORT_ATTEMPTS => {
                    eprintln!("Grok billing transport attempt {attempt} failed: {error}");
                    attempt += 1;
                    tokio::time::sleep(BILLING_RETRY_DELAY).await;
                }
                Err(error) => {
                    eprintln!("Grok billing transport failed: {error}");
                    return Err(upstream_error("Grok billing request failed"));
                }
            }
        };
        let response: BillingResponse = response_json(response, "Grok billing").await?;
        normalize_billing(account_id, response)
    }

    pub(crate) fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserResponse {
    user_id: String,
}

#[derive(Deserialize)]
struct BillingResponse {
    config: Option<BillingConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BillingConfig {
    credit_usage_percent: Option<f64>,
    current_period: Option<UsagePeriod>,
    on_demand_cap: Option<Cent>,
    on_demand_used: Option<Cent>,
    prepaid_balance: Option<Cent>,
    #[serde(default)]
    product_usage: Vec<ProductUsage>,
}

#[derive(Deserialize)]
struct Cent {
    #[serde(default)]
    val: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsagePeriod {
    #[serde(rename = "type")]
    period_type: Option<String>,
    start: Option<String>,
    end: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProductUsage {
    product: String,
    usage_percent: Option<f64>,
}

fn normalize_billing(
    account_id: &str,
    response: BillingResponse,
) -> Result<ProviderQuotaSnapshot, ProviderQuotaError> {
    let config = response.config.ok_or_else(|| {
        ProviderQuotaError::new(
            ProviderQuotaErrorKind::InvalidResponse,
            "Grok billing response is missing config",
        )
    })?;
    let mut groups = Vec::new();
    let mut warnings = Vec::new();

    if config.credit_usage_percent.is_some() || config.current_period.is_some() {
        let period = config
            .current_period
            .as_ref()
            .map(|period| normalize_period(period, &mut warnings));
        let used = config.credit_usage_percent.map(|value| {
            normalized_percent(value, "aggregate_usage_percent_clamped", &mut warnings)
        });
        let remaining = used.map(|value| (100.0 - value).max(0.0));
        let breakdown = config
            .product_usage
            .iter()
            .filter_map(|usage| normalize_product_usage(usage, &mut warnings))
            .collect();
        groups.push(QuotaGroup {
            key: "grok".to_owned(),
            scope: QuotaGroupScope::Aggregate,
            audience: QuotaGroupAudience::Shared,
            attributes: Default::default(),
            metrics: vec![QuotaMetric {
                key: "included_usage".to_owned(),
                kind: QuotaMetricKind::Usage,
                unit: QuotaUnit::Percent,
                used: used.map(QuotaAmount::Decimal),
                remaining: remaining.map(QuotaAmount::Decimal),
                limit: Some(QuotaAmount::Decimal(100.0)),
                period,
                breakdown,
            }],
        });
    }

    let mut billing_metrics = Vec::new();
    if config.on_demand_cap.is_some() || config.on_demand_used.is_some() {
        let limit = config.on_demand_cap.as_ref().map(|value| value.val);
        let used = config.on_demand_used.as_ref().map(|value| value.val);
        let remaining = match (limit, used) {
            (Some(limit), Some(used)) => Some(limit.saturating_sub(used).max(0)),
            _ => None,
        };
        billing_metrics.push(QuotaMetric {
            key: "on_demand".to_owned(),
            kind: QuotaMetricKind::Usage,
            unit: QuotaUnit::UsdCents,
            used: used.map(QuotaAmount::Integer),
            remaining: remaining.map(QuotaAmount::Integer),
            limit: limit.map(QuotaAmount::Integer),
            period: None,
            breakdown: Vec::new(),
        });
    }
    if let Some(prepaid_balance) = config.prepaid_balance {
        billing_metrics.push(QuotaMetric {
            key: "prepaid".to_owned(),
            kind: QuotaMetricKind::Balance,
            unit: QuotaUnit::UsdCents,
            used: None,
            remaining: Some(QuotaAmount::Integer(prepaid_balance.val)),
            limit: None,
            period: None,
            breakdown: Vec::new(),
        });
    }
    if !billing_metrics.is_empty() {
        groups.push(QuotaGroup {
            key: "billing".to_owned(),
            scope: QuotaGroupScope::Billing,
            audience: QuotaGroupAudience::OwnerOnly,
            attributes: Default::default(),
            metrics: billing_metrics,
        });
    }

    if groups.is_empty() {
        return Err(ProviderQuotaError::new(
            ProviderQuotaErrorKind::InvalidResponse,
            "Grok billing response did not contain supported quota fields",
        ));
    }

    Ok(ProviderQuotaSnapshot {
        account_id: account_id.to_owned(),
        provider: ProviderKind::Grok,
        fetched_at: unix_timestamp(),
        last_observed_at: None,
        groups,
        warnings,
    })
}

fn normalize_period(period: &UsagePeriod, warnings: &mut Vec<String>) -> QuotaPeriod {
    let kind = match period.period_type.as_deref() {
        Some(value) if value.contains("WEEKLY") => QuotaPeriodKind::Weekly,
        Some(value) if value.contains("MONTHLY") => QuotaPeriodKind::Monthly,
        _ => QuotaPeriodKind::Unknown,
    };
    QuotaPeriod {
        kind,
        starts_at: parse_timestamp(
            period.start.as_deref(),
            "invalid_current_period_start",
            warnings,
        ),
        ends_at: parse_timestamp(
            period.end.as_deref(),
            "invalid_current_period_end",
            warnings,
        ),
        duration_seconds: None,
    }
}

fn normalize_product_usage(
    usage: &ProductUsage,
    warnings: &mut Vec<String>,
) -> Option<QuotaBreakdown> {
    let usage_percent = usage.usage_percent?;
    let (key, label) = match usage.product.trim() {
        "GrokBuild" => ("grok_build", "GrokBuild"),
        "GrokChat" => ("grok_chat", "GrokChat"),
        _ => {
            push_warning(warnings, "unknown_product_usage_ignored");
            return None;
        }
    };
    Some(QuotaBreakdown {
        key: key.to_owned(),
        label: label.to_owned(),
        used: QuotaAmount::Decimal(normalized_percent(
            usage_percent,
            "product_usage_percent_clamped",
            warnings,
        )),
    })
}

fn normalized_percent(value: f64, warning: &str, warnings: &mut Vec<String>) -> f64 {
    let normalized = value.clamp(0.0, 100.0);
    if normalized != value {
        push_warning(warnings, warning);
    }
    normalized
}

fn parse_timestamp(value: Option<&str>, warning: &str, warnings: &mut Vec<String>) -> Option<i64> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    match OffsetDateTime::parse(value, &Rfc3339) {
        Ok(timestamp) => Some(timestamp.unix_timestamp()),
        Err(_) => {
            push_warning(warnings, warning);
            None
        }
    }
}

fn push_warning(warnings: &mut Vec<String>, warning: &str) {
    if !warnings.iter().any(|value| value == warning) {
        warnings.push(warning.to_owned());
    }
}

async fn response_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    operation: &str,
) -> Result<T, ProviderQuotaError> {
    let status = response.status();
    if !status.is_success() {
        return Err(status_error(operation, status));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("missing")
        .to_owned();
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(ProviderQuotaError::new(
            ProviderQuotaErrorKind::InvalidResponse,
            format!("{operation} returned non-JSON content type {content_type}"),
        ));
    }
    let body = collect_bounded_body(response.bytes_stream(), MAX_RESPONSE_SIZE)
        .await
        .map_err(|error| match error {
            BoundedBodyError::Read(_) => {
                upstream_error(format!("failed to read {operation} response"))
            }
            BoundedBodyError::TooLarge => ProviderQuotaError::new(
                ProviderQuotaErrorKind::InvalidResponse,
                format!("{operation} response was too large"),
            ),
        })?;
    serde_json::from_slice(&body).map_err(|error| {
        let detail = match error.classify() {
            serde_json::error::Category::Data => format!(
                "{operation} returned unexpected data at line {}, column {}",
                error.line(),
                error.column()
            ),
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof => format!(
                "{operation} returned invalid JSON at line {}, column {}",
                error.line(),
                error.column()
            ),
            serde_json::error::Category::Io => {
                format!("failed to decode {operation} response")
            }
        };
        ProviderQuotaError::new(ProviderQuotaErrorKind::InvalidResponse, detail)
    })
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

fn upstream_error(message: impl Into<String>) -> ProviderQuotaError {
    ProviderQuotaError::new(ProviderQuotaErrorKind::Upstream, message)
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Router,
        extract::{OriginalUri, State},
        http::HeaderMap,
        routing::get,
    };
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Clone, Default)]
    struct CapturedRequests {
        user_headers: Arc<Mutex<Option<HeaderMap>>>,
        billing: Arc<Mutex<Option<(HeaderMap, String)>>>,
    }

    async fn user_handler(
        State(captured): State<CapturedRequests>,
        headers: HeaderMap,
    ) -> axum::Json<serde_json::Value> {
        *captured.user_headers.lock().expect("user headers lock") = Some(headers);
        axum::Json(serde_json::json!({"userId": "upstream-user"}))
    }

    async fn billing_handler(
        State(captured): State<CapturedRequests>,
        OriginalUri(uri): OriginalUri,
        headers: HeaderMap,
    ) -> (
        [(axum::http::header::HeaderName, &'static str); 1],
        &'static str,
    ) {
        *captured.billing.lock().expect("billing request lock") = Some((headers, uri.to_string()));
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            include_str!("fixtures/billing_current.json"),
        )
    }

    #[test]
    fn normalizes_current_credits_response() {
        let response: BillingResponse =
            serde_json::from_str(include_str!("fixtures/billing_current.json"))
                .expect("current fixture");
        let snapshot = normalize_billing("grok-main", response).expect("normalized quota");

        assert_eq!(snapshot.groups.len(), 2);
        assert_eq!(snapshot.groups[0].audience, QuotaGroupAudience::Shared);
        assert_eq!(snapshot.groups[1].audience, QuotaGroupAudience::OwnerOnly);
        let usage = &snapshot.groups[0].metrics[0];
        assert_eq!(usage.used, Some(QuotaAmount::Decimal(75.0)));
        assert_eq!(usage.remaining, Some(QuotaAmount::Decimal(25.0)));
        assert_eq!(usage.breakdown.len(), 2);
        assert_eq!(
            usage.period.as_ref().map(|period| period.kind),
            Some(QuotaPeriodKind::Weekly)
        );
        assert_eq!(snapshot.groups[1].metrics.len(), 2);
    }

    #[tokio::test]
    async fn sends_current_user_and_billing_request_contract() {
        let captured = CapturedRequests::default();
        let app = Router::new()
            .route("/v1/user", get(user_handler))
            .route("/v1/billing", get(billing_handler))
            .with_state(captured.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind quota server");
        let address = listener.local_addr().expect("quota server address");
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let client = GrokQuotaClient::with_base_url(format!("http://{address}/v1"));
        let credentials = GrokCredentials::from_access_token("quota-token");

        let user_id = client
            .fetch_user_id(&credentials)
            .await
            .expect("fetch user ID");
        client
            .fetch_quota("grok-main", &credentials, &user_id)
            .await
            .expect("fetch quota");
        server.abort();

        let user_headers = captured
            .user_headers
            .lock()
            .expect("user headers lock")
            .clone()
            .expect("captured user headers");
        assert_eq!(
            user_headers
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer quota-token")
        );
        assert_eq!(
            user_headers
                .get("x-grok-client-version")
                .and_then(|value| value.to_str().ok()),
            Some("1.0.0")
        );
        assert!(user_headers.get("x-userid").is_none());

        let (billing_headers, uri) = captured
            .billing
            .lock()
            .expect("billing request lock")
            .clone()
            .expect("captured billing request");
        assert_eq!(uri, "/v1/billing?format=credits");
        assert_eq!(
            billing_headers
                .get("x-userid")
                .and_then(|value| value.to_str().ok()),
            Some("upstream-user")
        );
        assert_eq!(
            billing_headers
                .get("x-xai-token-auth")
                .and_then(|value| value.to_str().ok()),
            Some("xai-grok-cli")
        );
        assert!(billing_headers.get(reqwest::header::CONTENT_TYPE).is_none());
    }

    #[test]
    fn missing_product_usage_keeps_aggregate_quota() {
        let mut response: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/billing_current.json"))
                .expect("current fixture");
        response["config"]
            .as_object_mut()
            .expect("config")
            .remove("productUsage");
        let response: BillingResponse = serde_json::from_value(response).expect("billing response");
        let snapshot = normalize_billing("grok-main", response).expect("normalized quota");

        assert!(snapshot.groups[0].metrics[0].breakdown.is_empty());
        assert_eq!(
            snapshot.groups[0].metrics[0].used,
            Some(QuotaAmount::Decimal(75.0))
        );
    }

    #[test]
    fn product_without_usage_percent_is_ignored() {
        let mut response: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/billing_current.json"))
                .expect("current fixture");
        response["config"]["productUsage"]
            .as_array_mut()
            .expect("product usage")
            .push(serde_json::json!({"product": "GrokCode"}));
        let response: BillingResponse = serde_json::from_value(response).expect("billing response");
        let snapshot = normalize_billing("grok-main", response).expect("normalized quota");

        assert_eq!(snapshot.groups[0].metrics[0].breakdown.len(), 2);
    }
}
