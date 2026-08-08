//! End-to-end usage tracking: a real HTTP request, a real Codex upstream, and a
//! real SQLite database, asserting what actually gets recorded.
//!
//! These exist because wiring is where the pieces stop agreeing with each other,
//! and because the properties they check fail silently: an absent count must never
//! become a zero, a refresh retry must be a second attempt rather than a lost one,
//! a cost must come out exact to the last digit, and no session may ever read
//! another owner's usage.

use std::{
    convert::Infallible,
    future::IntoFuture,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{Response, StatusCode},
    routing::{get, post},
};
use futures_util::{StreamExt, stream};
use provider_auth::{ApiKeyAuthenticator, AuthService};
use provider_core::{
    AccountId, ProviderKind, ProviderModelPricingSource, ProviderVisibility, ProxyService,
    usage::{TokenMetric, TokenUnknownReason},
};
use provider_drivers::codex::CodexDriver;
use provider_management::ProviderManager;
use provider_protocol::DefaultProtocolBridge;
use provider_runtime::ProviderRuntimeCatalog;
use provider_storage::{SqliteAccountRepository, SqliteUsageRepository};
use provider_usage::{
    CatalogPrices, CatalogRefresher, CostReason, CostStatus, DEFAULT_WRITE_QUEUE, DeliveryOutcome,
    DispatchEvidence, ExecutionOutcome, LogicalStatus, PriceResolution, RefreshOutcome,
    TrackingState, UsageRepository, UsageTracking, UsageWriter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// A Codex `response.completed` reporting input and output but no cache details
/// and no total, which is exactly the shape that must not become zeroes. It names
/// the model it served, as a real terminal does.
const COMPLETED_STREAM: &[u8] = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5.5\",\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n\n";

/// The shape Codex actually sends: the cached portion of the input is broken out,
/// which is what makes the two input rates separable.
const COMPLETED_WITH_CACHE: &[u8] = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":120,\"input_tokens_details\":{\"cached_tokens\":100},\"output_tokens\":8,\"total_tokens\":128}}}\n\n";

const PARTIAL_STREAM: &[u8] =
    b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n";

#[derive(Clone, Default)]
struct Upstream {
    /// Always answer `401`, so the runtime refreshes and calls a second time.
    always_unauthorized: bool,
    /// Report the cached split, as a real Codex response does.
    with_cache_details: bool,
    /// Send one content event and then wait, so a test can disconnect mid-stream.
    stall_after_chunk: bool,
    calls: Arc<AtomicUsize>,
}

async fn models() -> &'static str {
    r#"{"data":[{"id":"gpt-5.5","owned_by":"openai"}]}"#
}

async fn responses(State(state): State<Upstream>, _request: Request) -> Response<Body> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    if state.always_unauthorized {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":{"code":"invalid_token"}}"#))
            .expect("unauthorized response");
    }
    if state.stall_after_chunk {
        let body = stream::once(async { Ok::<_, Infallible>(Bytes::from_static(PARTIAL_STREAM)) })
            .chain(stream::pending());
        return Response::builder()
            .status(StatusCode::OK)
            .header(reqwest::header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(body))
            .expect("partial stream response");
    }
    let stream = if state.with_cache_details {
        COMPLETED_WITH_CACHE
    } else {
        COMPLETED_STREAM
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(reqwest::header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from(Bytes::from_static(stream)))
        .expect("stream response")
}

async fn refresh() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"access_token":"new-access"}"#))
        .expect("refresh response")
}

async fn spawn(router: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("test server address");
    tokio::spawn(axum::serve(listener, router).into_future());
    format!("http://{address}")
}

struct Harness {
    server_url: String,
    api_key: String,
    usage: Arc<SqliteUsageRepository>,
    writer: Arc<UsageWriter>,
    upstream_calls: Arc<AtomicUsize>,
}

/// Everything below the HTTP router: storage, runtime, one Codex account and one
/// API key. Tests compose their own tracking on top so they can choose how prices
/// are resolved.
struct Deployment {
    service: ProxyService,
    api_keys: ApiKeyAuthenticator,
    api_key: String,
    auth: AuthService,
    manager: ProviderManager,
    owner_user_id: String,
    account_id: AccountId,
    usage: Arc<SqliteUsageRepository>,
    writer: Arc<UsageWriter>,
}

async fn harness(always_unauthorized: bool) -> Harness {
    harness_with_options(always_unauthorized, false).await
}

async fn harness_with_options(always_unauthorized: bool, stall_after_chunk: bool) -> Harness {
    let upstream_state = Upstream {
        always_unauthorized,
        with_cache_details: false,
        stall_after_chunk,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let upstream_calls = upstream_state.calls.clone();
    let upstream_url = spawn(
        Router::new()
            .route("/codex/models", get(models))
            .route("/codex/responses", post(responses))
            .route("/oauth/token", post(refresh))
            .with_state(upstream_state),
    )
    .await;

    let deployment = deployment(&upstream_url).await;
    let tracking = Arc::new(UsageTracking::new(
        deployment.usage.clone(),
        deployment.writer.clone(),
    ));
    let server_url = spawn(provider_server::router_with_usage(
        deployment.service.clone(),
        deployment.api_keys.clone(),
        Some(tracking),
    ))
    .await;

    Harness {
        server_url,
        api_key: deployment.api_key,
        usage: deployment.usage,
        writer: deployment.writer,
        upstream_calls,
    }
}

async fn deployment(upstream_url: &str) -> Deployment {
    deployment_with_pricing(upstream_url, None).await
}

async fn deployment_with_pricing(
    upstream_url: &str,
    pricing: Option<Arc<CatalogPrices>>,
) -> Deployment {
    let repository = Arc::new(
        SqliteAccountRepository::in_memory()
            .await
            .expect("repository"),
    );
    let auth = AuthService::new(repository.clone());
    let now = unix_timestamp();
    let grant = auth
        .setup(
            "admin".to_owned(),
            SecretString::from("secret".to_owned()),
            now,
        )
        .await
        .expect("initial setup");

    let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
    runtime
        .register_driver(CodexDriver::for_test(upstream_url, upstream_url))
        .expect("register Codex driver");
    let manager = match pricing {
        Some(pricing) => ProviderManager::with_model_pricing_catalog(
            repository.clone(),
            runtime.clone(),
            pricing,
        ),
        None => ProviderManager::new(repository.clone(), runtime.clone()),
    };
    let created_account = manager
        .create_credential_account(
            grant.user.id.as_str(),
            ProviderKind::Codex,
            "Codex".to_owned(),
            "default".to_owned(),
            SecretString::from(
                json!({
                    "type": "codex",
                    "auth_kind": "oauth",
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                    "id_token": "e30.e30.sig",
                    "last_refreshed_at": now
                })
                .to_string(),
            ),
            ProviderVisibility::Private,
            now,
        )
        .await
        .expect("create Codex account");
    let api_keys = ApiKeyAuthenticator::load(repository.clone())
        .await
        .expect("API key index");
    let created_key = api_keys
        .create(
            &grant.user.id,
            "default".to_owned(),
            "test".to_owned(),
            None,
            None,
            now,
        )
        .await
        .expect("create API key");

    let usage = Arc::new(repository.usage_repository());
    let writer = Arc::new(UsageWriter::spawn(usage.clone(), DEFAULT_WRITE_QUEUE));
    let service = ProxyService::with_router(runtime, Arc::new(DefaultProtocolBridge));

    Deployment {
        service,
        api_keys,
        api_key: created_key.key.expose_secret().to_owned(),
        auth,
        manager,
        owner_user_id: grant.user.id.as_str().to_owned(),
        account_id: created_account.account.id,
        usage,
        writer,
    }
}

impl Harness {
    async fn post_responses(&self) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/v1/responses", self.server_url))
            .bearer_auth(&self.api_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(json!({ "model": "gpt-5.5", "stream": false, "input": "hello" }).to_string())
            .send()
            .await
            .expect("Responses request")
    }
}

fn unix_timestamp() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("timestamp fits")
}

#[tokio::test]
async fn a_successful_response_records_what_the_provider_actually_reported() {
    let harness = harness(false).await;
    let body = harness
        .post_responses()
        .await
        .text()
        .await
        .expect("response body");
    assert!(body.contains("response.completed"), "the proxy still works");

    assert!(
        harness.writer.drain(Duration::from_secs(10)).await,
        "usage writes must complete"
    );
    let request_id = harness
        .usage
        .oldest_request_id()
        .await
        .expect("request lookup")
        .expect("a logical request was recorded");

    let stored = harness
        .usage
        .load_logical_request(&request_id)
        .await
        .expect("load logical")
        .expect("logical present");
    assert_eq!(stored.status, LogicalStatus::Succeeded);
    assert_eq!(
        stored.execution,
        Some(ExecutionOutcome::StableSuccessTerminal),
        "response.completed is what proves this succeeded"
    );
    assert_eq!(stored.delivery, Some(DeliveryOutcome::CleanEof));
    assert_eq!(stored.tracking, TrackingState::Complete);
    assert_eq!(stored.start.client_model_raw.as_deref(), Some("gpt-5.5"));

    let attempts = harness
        .usage
        .load_attempts(&request_id)
        .await
        .expect("load attempts");
    assert_eq!(attempts.len(), 1, "one upstream call is one attempt");
    let attempt = &attempts[0];
    assert_eq!(attempt.provider, ProviderKind::Codex);
    assert_eq!(
        attempt.dispatch_evidence,
        DispatchEvidence::ResponseObserved
    );
    assert_eq!(
        stored.final_attempt_id.as_deref(),
        Some(attempt.attempt_id.as_str())
    );
    // Read off the wire, not assumed: this is the only thing that can reveal a
    // provider serving a model other than the one the estimate was priced for.
    assert_eq!(attempt.configured_model.as_deref(), Some("gpt-5.5"));
    assert_eq!(attempt.provider_reported_model.as_deref(), Some("gpt-5.5"));

    // What the provider reported, and — just as important — what it did not.
    let observed = &attempt.observation;
    assert_eq!(
        observed.effective_input_tokens,
        TokenMetric::ProviderReported { value: 2 }
    );
    assert_eq!(
        observed.output_tokens,
        TokenMetric::ProviderReported { value: 1 }
    );
    assert_eq!(
        observed.cache_read_input_tokens,
        TokenMetric::NotReported,
        "absent cache details are not a zero and not a cache miss"
    );
    assert_eq!(
        observed.uncached_input_tokens,
        TokenMetric::Unknown {
            reason: TokenUnknownReason::Indeterminate
        },
        "input includes cache, so without the cached split the parts are unknown"
    );
    assert_eq!(
        observed.total_tokens,
        TokenMetric::NotReported,
        "an unreported total stays unreported rather than being invented"
    );

    // The selected provider model has no saved price, so the cost is honestly
    // unavailable rather than falling back to a request-time catalog lookup.
    assert_eq!(attempt.price, PriceResolution::ModelMappingMissing);
    assert_eq!(attempt.cost.status, CostStatus::Unavailable);
    assert_eq!(attempt.cost.reasons, vec![CostReason::ModelMappingMissing]);
}

#[tokio::test]
async fn an_authenticated_invalid_request_is_recorded_without_an_attempt() {
    let harness = harness(false).await;
    let status = reqwest::Client::new()
        .post(format!("{}/v1/responses", harness.server_url))
        .bearer_auth(&harness.api_key)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{")
        .send()
        .await
        .expect("invalid request")
        .status();
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert!(harness.writer.drain(Duration::from_secs(10)).await);
    let request_id = harness
        .usage
        .oldest_request_id()
        .await
        .expect("request lookup")
        .expect("authenticated request was recorded");
    let stored = harness
        .usage
        .load_logical_request(&request_id)
        .await
        .expect("load logical")
        .expect("logical present");
    assert_eq!(stored.status, LogicalStatus::Failed);
    assert_eq!(stored.execution, Some(ExecutionOutcome::StableFailure));
    assert_eq!(stored.delivery, Some(DeliveryOutcome::ErrorBeforeBytes));
    assert_eq!(stored.final_attempt_id, None);
    assert!(
        harness
            .usage
            .load_attempts(&request_id)
            .await
            .expect("load attempts")
            .is_empty(),
        "pre-validation failure must not invent an upstream attempt"
    );
}

#[tokio::test]
async fn a_client_drop_closes_the_attempt_before_the_logical_request() {
    let harness = harness_with_options(false, true).await;
    let mut response = harness.post_responses().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.chunk().await.expect("read first chunk").is_some(),
        "the response must have started before it is dropped"
    );
    drop(response);

    let request_id = harness
        .usage
        .oldest_request_id()
        .await
        .expect("request lookup")
        .expect("logical request started");
    let stored = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(harness.writer.drain(Duration::from_secs(1)).await);
            let stored = harness
                .usage
                .load_logical_request(&request_id)
                .await
                .expect("load logical")
                .expect("logical present");
            if stored.status.is_terminal() {
                break stored;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client drop should terminate tracking");

    assert_eq!(stored.status, LogicalStatus::Canceled);
    assert_eq!(stored.delivery, Some(DeliveryOutcome::ClientDrop));
    let attempts = harness
        .usage
        .load_attempts(&request_id)
        .await
        .expect("load attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        stored.final_attempt_id.as_deref(),
        Some(attempts[0].attempt_id.as_str()),
        "the attempt must close before logical terminal snapshots final_attempt_id"
    );
}

#[tokio::test]
async fn a_refresh_retry_records_two_attempts_under_one_request() {
    // The upstream rejects every call, so the runtime refreshes and calls again:
    // one logical request, two real upstream calls, two attempts.
    let harness = harness(true).await;
    let status = harness.post_responses().await.status();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the failure still reaches the client"
    );
    assert_eq!(harness.upstream_calls.load(Ordering::SeqCst), 2);

    assert!(
        harness.writer.drain(Duration::from_secs(10)).await,
        "usage writes must complete"
    );
    let request_id = harness
        .usage
        .oldest_request_id()
        .await
        .expect("request lookup")
        .expect("a logical request was recorded");

    let attempts = harness
        .usage
        .load_attempts(&request_id)
        .await
        .expect("load attempts");
    assert_eq!(
        attempts.len(),
        2,
        "a refresh retry must not be folded into one attempt"
    );
    for attempt in &attempts {
        assert_eq!(
            attempt.dispatch_evidence,
            DispatchEvidence::ResponseObserved,
            "a 401 proves the provider answered"
        );
        assert_eq!(attempt.cost.status, CostStatus::Unavailable);
    }
    assert_eq!(attempts[0].sequence.0, 1);
    assert_eq!(attempts[1].sequence.0, 2);

    let stored = harness
        .usage
        .load_logical_request(&request_id)
        .await
        .expect("load logical")
        .expect("logical present");
    assert_eq!(stored.status, LogicalStatus::Failed);
    assert_eq!(stored.delivery, Some(DeliveryOutcome::ErrorBeforeBytes));
    assert_eq!(
        stored.final_attempt_id.as_deref(),
        Some(attempts[1].attempt_id.as_str()),
        "the second attempt is the one the client's failure came from"
    );
}

/// A models.dev-shaped catalog for the model this test proxies. The reasoning
/// price is present on purpose: the Codex contract says reasoning is already
/// inside `output_tokens`, so it must *not* be charged again.
const CATALOG_BODY: &str = r#"{
  "openai": {
    "id": "openai",
    "models": {
      "gpt-5.5": {
        "id": "gpt-5.5",
        "cost": { "input": 1.25, "output": 10, "cache_read": 0.125, "reasoning": 5 }
      }
    }
  }
}"#;

async fn catalog_body() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ETAG, "\"catalog-v1\"")
        .body(Body::from(CATALOG_BODY))
        .expect("catalog response")
}

#[tokio::test]
async fn a_priced_response_records_an_exact_cost() {
    // The full path: fetch a catalog over HTTP, install it, proxy a request, and
    // check the money that lands in the database.
    let upstream_state = Upstream {
        always_unauthorized: false,
        with_cache_details: true,
        stall_after_chunk: false,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let upstream_url = spawn(
        Router::new()
            .route("/codex/models", get(models))
            .route("/codex/responses", post(responses))
            .route("/oauth/token", post(refresh))
            .route("/api.json", get(catalog_body))
            .with_state(upstream_state),
    )
    .await;

    let prices = Arc::new(CatalogPrices::new());
    let deployment = deployment_with_pricing(&upstream_url, Some(prices.clone())).await;

    // Refresh from the mock catalog, then refresh the provider model so the
    // exact-id price is saved and loaded into runtime before the request.
    let refresher = CatalogRefresher::new(
        deployment.usage.clone(),
        Arc::new(
            provider_server::HttpCatalogSource::new(format!("{upstream_url}/api.json"))
                .expect("catalog source"),
        ),
        prices.clone(),
        provider_usage::system_clock_ms,
    );
    assert_eq!(refresher.refresh_once().await, RefreshOutcome::Installed);
    deployment
        .manager
        .refresh_models(
            &deployment.owner_user_id,
            &deployment.account_id,
            unix_timestamp(),
        )
        .await
        .expect("refresh provider models with catalog pricing");

    let tracking = Arc::new(UsageTracking::new(
        deployment.usage.clone(),
        deployment.writer.clone(),
    ));
    let server_url = spawn(provider_server::router_with_usage(
        deployment.service.clone(),
        deployment.api_keys.clone(),
        Some(tracking),
    ))
    .await;

    let body = reqwest::Client::new()
        .post(format!("{server_url}/v1/responses"))
        .bearer_auth(&deployment.api_key)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "model": "gpt-5.5", "stream": false, "input": "hello" }).to_string())
        .send()
        .await
        .expect("Responses request")
        .text()
        .await
        .expect("response body");
    assert!(body.contains("response.completed"));

    assert!(
        deployment.writer.drain(Duration::from_secs(10)).await,
        "usage writes must complete"
    );
    let request_id = deployment
        .usage
        .oldest_request_id()
        .await
        .expect("request lookup")
        .expect("a logical request was recorded");
    let attempts = deployment
        .usage
        .load_attempts(&request_id)
        .await
        .expect("load attempts");
    let attempt = &attempts[0];

    // 120 input of which 100 cached, so 20 uncached; 8 output.
    assert_eq!(
        attempt.observation.uncached_input_tokens,
        TokenMetric::DerivedFromReported {
            value: 20,
            rule_version: 1
        }
    );
    assert_eq!(
        attempt.observation.cache_read_input_tokens,
        TokenMetric::ProviderReported { value: 100 }
    );

    let record = attempt.price.resolved().expect("prices were resolved");
    assert_eq!(record.source(), Some(ProviderModelPricingSource::Catalog));
    assert_eq!(record.catalog_model_id(), None);
    assert_eq!(record.catalog_revision(), None);

    // 20 @ $1.25/M + 100 @ $0.125/M + 8 @ $10/M = $0.0001175 exactly.
    //
    // The catalog also carries a reasoning price. Charging it would be wrong:
    // this contract puts reasoning inside output_tokens, so it is already paid
    // for, and a second charge would silently inflate every reasoning response.
    assert_eq!(
        attempt.cost.status,
        CostStatus::CompleteForObservedCatalogComponents,
        "every observed component had a price"
    );
    assert_eq!(attempt.cost.reasons, Vec::new());
    assert_eq!(
        attempt.cost.total_known.to_decimal_string(),
        "0.00011750000000"
    );
}

/// Log in and return the access token, so the usage endpoints can be called the
/// way a dashboard calls them.
async fn login(server_url: &str, username: &str, password: &str) -> String {
    let text = reqwest::Client::new()
        .post(format!("{server_url}/api/v1/auth/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "username": username, "password": password }).to_string())
        .send()
        .await
        .expect("login request")
        .text()
        .await
        .expect("login body");
    let body: Value = serde_json::from_str(&text).expect("login json");
    body["data"]["access_token"]
        .as_str()
        .expect("access token")
        .to_owned()
}

async fn get_usage(server_url: &str, token: &str, path: &str) -> (StatusCode, Value) {
    let response = reqwest::Client::new()
        .get(format!("{server_url}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .expect("usage request");
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_usage_endpoints_only_ever_report_the_logged_in_user() {
    // Two users, each with their own request. Neither may see the other's, and
    // that must hold even though one of them is the super_admin who set the
    // deployment up.
    let upstream_state = Upstream {
        always_unauthorized: false,
        with_cache_details: true,
        stall_after_chunk: false,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let upstream_url = spawn(
        Router::new()
            .route("/codex/models", get(models))
            .route("/codex/responses", post(responses))
            .route("/oauth/token", post(refresh))
            .with_state(upstream_state),
    )
    .await;

    let deployment = deployment(&upstream_url).await;
    let tracking = Arc::new(UsageTracking::new(
        deployment.usage.clone(),
        deployment.writer.clone(),
    ));
    let services = provider_server::UsageServices {
        tracking,
        query: deployment.usage.clone(),
    };
    let server_url = spawn(provider_server::router_with_management_and_usage(
        deployment.service.clone(),
        deployment.manager.clone(),
        deployment.auth.clone(),
        deployment.api_keys.clone(),
        Some(services),
        None,
    ))
    .await;

    // The admin proxies one request, so there is usage to attribute.
    reqwest::Client::new()
        .post(format!("{server_url}/v1/responses"))
        .bearer_auth(&deployment.api_key)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "model": "gpt-5.5", "stream": false, "input": "hi" }).to_string())
        .send()
        .await
        .expect("proxy request");
    assert!(deployment.writer.drain(Duration::from_secs(10)).await);

    let admin_token = login(&server_url, "admin", "secret").await;
    let (status, body) = get_usage(&server_url, &admin_token, "/api/v1/usage/overview").await;
    assert_eq!(status, StatusCode::OK);
    let overview = &body["data"];
    assert_eq!(overview["logical_requests"], 1);
    assert_eq!(overview["tokens"]["effective_input"], 120);
    assert_eq!(overview["tokens"]["cache_read_input"], 100);
    assert!(overview["cost"]["usd"].is_null());

    // A second user with no usage of their own sees nothing, not the admin's.
    let created_text = reqwest::Client::new()
        .post(format!("{server_url}/api/v1/users"))
        .bearer_auth(&admin_token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "username": "other", "password": "other-secret" }).to_string())
        .send()
        .await
        .expect("create user")
        .text()
        .await
        .expect("create user body");
    let created: Value = serde_json::from_str(&created_text).expect("create user json");
    assert!(
        created["data"]["id"].is_string(),
        "second user was created: {created}"
    );

    let other_token = login(&server_url, "other", "other-secret").await;
    let (status, body) = get_usage(&server_url, &other_token, "/api/v1/usage/overview").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"]["logical_requests"], 0,
        "another user's usage must be invisible"
    );

    // And the admin's own request is not readable by id either.
    let request_id = deployment
        .usage
        .oldest_request_id()
        .await
        .expect("lookup")
        .expect("a request was recorded");
    let (status, _) = get_usage(
        &server_url,
        &other_token,
        &format!("/api/v1/usage/requests/{request_id}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "reading another user's request must be indistinguishable from missing"
    );

    let (status, body) = get_usage(
        &server_url,
        &admin_token,
        &format!("/api/v1/usage/requests/{request_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let attempt = &body["data"]["attempt"];
    assert!(
        attempt["cost"]["usd"].is_null(),
        "an unavailable cost is absent, never 0"
    );
    assert!(attempt["price"]["input_per_million_usd"].is_null());
}

#[tokio::test]
async fn the_usage_endpoints_require_a_session_and_validate_their_input() {
    let upstream_url = spawn(
        Router::new()
            .route("/codex/models", get(models))
            .route("/codex/responses", post(responses))
            .route("/oauth/token", post(refresh))
            .with_state(Upstream::default()),
    )
    .await;
    let deployment = deployment(&upstream_url).await;
    let services = provider_server::UsageServices {
        tracking: Arc::new(UsageTracking::new(
            deployment.usage.clone(),
            deployment.writer.clone(),
        )),
        query: deployment.usage.clone(),
    };
    let server_url = spawn(provider_server::router_with_management_and_usage(
        deployment.service.clone(),
        deployment.manager.clone(),
        deployment.auth.clone(),
        deployment.api_keys.clone(),
        Some(services),
        None,
    ))
    .await;

    // No session at all.
    let anonymous = reqwest::Client::new()
        .get(format!("{server_url}/api/v1/usage/overview"))
        .send()
        .await
        .expect("anonymous request");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    // A proxy API key is not a dashboard session.
    let with_proxy_key = reqwest::Client::new()
        .get(format!("{server_url}/api/v1/usage/overview"))
        .bearer_auth(&deployment.api_key)
        .send()
        .await
        .expect("api key request");
    assert_eq!(
        with_proxy_key.status(),
        StatusCode::UNAUTHORIZED,
        "a proxy key must not read the dashboard"
    );

    let token = login(&server_url, "admin", "secret").await;

    // A range wider than retention is refused rather than silently truncated.
    let (status, body) = get_usage(
        &server_url,
        &token,
        "/api/v1/usage/overview?from_ms=0&to_ms=99999999999999",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["type"], "invalid_request_error");

    let (status, _) = get_usage(
        &server_url,
        &token,
        "/api/v1/usage/overview?from_ms=100&to_ms=100",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an empty range is refused");

    let (status, _) = get_usage(&server_url, &token, "/api/v1/usage/overview?unknown=1").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown fields are refused"
    );

    let (status, _) = get_usage(&server_url, &token, "/api/v1/usage/series?bucket=fortnight").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "removed usage APIs stay removed"
    );

    let (status, _) = get_usage(&server_url, &token, "/api/v1/usage/requests?limit=10").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "page size is server-owned");

    for filter in ["api_key_id", "model", "group"] {
        let path = format!("/api/v1/usage/requests?{filter}=%20");
        let (status, _) = get_usage(&server_url, &token, &path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "empty {filter} is refused");
    }

    let (status, _) = get_usage(&server_url, &token, "/api/v1/usage/requests?cursor=garbage").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = get_usage(&server_url, &token, "/api/v1/usage/health").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "removed usage APIs stay removed"
    );
}
