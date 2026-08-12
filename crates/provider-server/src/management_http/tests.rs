use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    routing::{get, post},
};
use provider_auth::{
    ApiKeyAuthenticator, AuthService, AuthenticatedSession, SessionId, UserId, UserRole,
    UserSummary,
};
use provider_core::{
    AccountId, CredentialKind, ProviderKind, ProviderManagementRepository, ProviderQuotaErrorKind,
    ProviderQuotaFreshness, ProviderQuotaSupport, ProxyService, StoredProviderModel,
};
use provider_drivers::{
    codex::CodexDriver, grok::GrokDriver, openai_compatible::OpenAiCompatibleDriver,
};
use provider_management::{
    CredentialProviderAccountInput, ProviderCredentialReplacement, ProviderManager,
};
use provider_protocol::DefaultProtocolBridge;
use provider_runtime::ProviderRuntimeCatalog;
use provider_storage::SqliteAccountRepository;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, pki_types::PrivateKeyDer},
};

use crate::{
    auth_http::MAX_AUTH_BODY_BYTES, http::MAX_MANAGEMENT_BODY_BYTES, router_with_management,
};

use super::{
    ModelPricingPatch, ProviderHealthParams, SetEnabledRequest, UpdateModelRequest,
    model_is_visible, require_super_admin, unix_timestamp, updated_pricing,
};

fn stored_model_with_metadata(metadata_json: &str) -> StoredProviderModel {
    StoredProviderModel {
        account_id: AccountId::new("account-1").expect("account ID"),
        upstream_model: "model-1".to_owned(),
        alias: None,
        enabled: true,
        available: true,
        routable: true,
        input_modalities: None,
        metadata_json: metadata_json.to_owned(),
        pricing: None,
        last_seen_at: None,
        created_at: 0,
        updated_at: 0,
    }
}

#[test]
fn hides_models_that_are_not_listed_by_upstream() {
    assert!(model_is_visible(&stored_model_with_metadata(
        r#"{"id":"public","visibility":"list"}"#,
    )));
    assert!(!model_is_visible(&stored_model_with_metadata(
        r#"{"id":"hidden","visibility":"hide"}"#,
    )));
    assert!(!model_is_visible(&stored_model_with_metadata(
        r#"{"id":"internal","visibility":"none"}"#,
    )));
    assert!(model_is_visible(&stored_model_with_metadata(
        r#"{"id":"compatible"}"#,
    )));
}

fn management_headers(session_token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("pode_session={session_token}")).expect("session cookie"),
    );
    headers
}

fn padded_json(prefix: &str, suffix: &str, size: usize) -> String {
    let padding = size
        .checked_sub(prefix.len() + suffix.len())
        .expect("requested JSON size");
    let mut body = String::with_capacity(size);
    body.push_str(prefix);
    body.extend(std::iter::repeat_n('a', padding));
    body.push_str(suffix);
    assert_eq!(body.len(), size);
    body
}

async fn assert_api_error(response: reqwest::Response, status: StatusCode, message: &str) {
    assert_eq!(response.status(), status);
    let body: Value = serde_json::from_str(
        &response
            .text()
            .await
            .expect("read management error response"),
    )
    .expect("management error response JSON");
    assert_eq!(body["error"]["type"], "invalid_request_error");
    assert_eq!(body["error"]["message"], message);
}

#[test]
fn provider_mutations_require_super_admin() {
    let session = |role| AuthenticatedSession {
        session_id: SessionId::new("provider-role-test").expect("session ID"),
        user: UserSummary {
            id: UserId::new("provider-role-user").expect("user ID"),
            username: "provider-role-user".to_owned(),
            role,
            enabled: true,
            created_at: 1,
            updated_at: 1,
        },
    };
    assert!(require_super_admin(&session(UserRole::SuperAdmin)).is_ok());
    let error = require_super_admin(&session(UserRole::User)).expect_err("ordinary user");
    assert_eq!(error.status, StatusCode::FORBIDDEN);
}

#[test]
fn management_requests_reject_unknown_fields() {
    assert!(
        serde_json::from_str::<SetEnabledRequest>(r#"{"enabled":true,"extra":true}"#,).is_err()
    );
    assert!(
        serde_json::from_str::<ProviderHealthParams>(r#"{"from_ms":1,"to_ms":2,"extra":true}"#,)
            .is_err()
    );
}

#[test]
fn model_update_pricing_request_is_strict_and_preserves_field_presence() {
    assert!(
        serde_json::from_str::<UpdateModelRequest>(
            r#"{"upstream_model":"model-a","alias":null,"enabled":true,"pricing_changed":false}"#,
        )
        .is_err(),
        "input_modalities is a required management contract field"
    );
    let missing: UpdateModelRequest = serde_json::from_str(
        r#"{"upstream_model":"model-a","alias":null,"enabled":true,"input_modalities":null,"pricing_changed":false}"#,
    )
    .expect("missing pricing field");
    assert!(matches!(missing.pricing, ModelPricingPatch::Missing));

    let null: UpdateModelRequest = serde_json::from_str(
        r#"{"upstream_model":"model-a","alias":null,"enabled":true,"input_modalities":null,"pricing_changed":true,"pricing":null}"#,
    )
    .expect("explicit null pricing");
    assert!(matches!(null.pricing, ModelPricingPatch::Null));

    let value: UpdateModelRequest = serde_json::from_str(
        r#"{"upstream_model":"model-a","alias":null,"enabled":true,"input_modalities":["video","audio","pdf","image","text"],"pricing_changed":true,"pricing":{"input":"1","output":"2","cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[{"threshold_tokens":200000,"input":"2","output":"4","cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null}]}}"#,
    )
    .expect("complete pricing object");
    let Ok(input_modalities) = value.input_modalities.into_modalities() else {
        panic!("valid input modalities");
    };
    assert_eq!(
        input_modalities,
        Some(vec![
            provider_core::ProviderModelInputModality::Video,
            provider_core::ProviderModelInputModality::Audio,
            provider_core::ProviderModelInputModality::Pdf,
            provider_core::ProviderModelInputModality::Image,
            provider_core::ProviderModelInputModality::Text,
        ])
    );
    let ModelPricingPatch::Value(value) = value.pricing else {
        panic!("pricing value");
    };
    let pricing = value.into_model_pricing().expect("valid pricing fields");
    assert_eq!(pricing.tiers.len(), 1);
    assert_eq!(pricing.tiers[0].threshold_tokens, 200_000);

    let duplicate: UpdateModelRequest = serde_json::from_str(
        r#"{"upstream_model":"model-a","alias":null,"enabled":true,"input_modalities":["text","text"],"pricing_changed":false}"#,
    )
    .expect("modality strings parse before contract validation");
    assert!(duplicate.input_modalities.into_modalities().is_err());
    let unknown: UpdateModelRequest = serde_json::from_str(
        r#"{"upstream_model":"model-a","alias":null,"enabled":true,"input_modalities":["text","future"],"pricing_changed":false}"#,
    )
    .expect("modality payload is validated after request shape parsing");
    assert!(unknown.input_modalities.into_modalities().is_err());

    assert!(
        serde_json::from_str::<UpdateModelRequest>(
            r#"{"upstream_model":"model-a","alias":null,"enabled":true,"input_modalities":null,"pricing_changed":true,"pricing":{"input":"1","output":"2","cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[{"threshold_tokens":200000,"input":"2","output":"4","cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"extra":true}]}}"#,
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<UpdateModelRequest>(
            r#"{"upstream_model":"model-a","alias":null,"enabled":true,"input_modalities":null,"pricing_changed":true,"pricing":{"input":"1","output":"2"}}"#,
        )
        .is_err()
    );

    assert!(matches!(
        updated_pricing(false, ModelPricingPatch::Missing),
        Ok(None)
    ));
    assert!(updated_pricing(false, ModelPricingPatch::Null).is_err());
    assert!(updated_pricing(true, ModelPricingPatch::Missing).is_err());
    assert!(matches!(
        updated_pricing(true, ModelPricingPatch::Null),
        Ok(Some(None))
    ));
}

async fn captured_models(
    State(authorization): State<Arc<Mutex<Vec<String>>>>,
    headers: HeaderMap,
) -> &'static str {
    authorization.lock().expect("authorization lock").push(
        headers
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
    );
    r#"{"data":[{"id":"model-a","owned_by":"test"}]}"#
}

async fn spawn_compatible_tls_upstream(
    authorization: Arc<Mutex<Vec<String>>>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let certified = rcgen::generate_simple_self_signed(vec!["api.example.test".to_owned()])
        .expect("compatible test certificate");
    let certificate = certified.cert.der().clone();
    let private_key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .expect("compatible TLS config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind compatible TLS upstream");
    let address = listener
        .local_addr()
        .expect("compatible TLS upstream address");
    let server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let authorization = authorization.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    if request.len() > 64 * 1024 {
                        return;
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let mut lines = request.lines();
                let path = lines
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default();
                let request_authorization = lines
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("authorization")
                                .then(|| value.trim().to_owned())
                        })
                    })
                    .unwrap_or_default();
                let (status, body) = if path == "/broken/models" {
                    ("502 Bad Gateway", r#"{"error":"failed"}"#)
                } else {
                    authorization
                        .lock()
                        .expect("authorization lock")
                        .push(request_authorization);
                    ("200 OK", r#"{"data":[{"id":"model-a","owned_by":"test"}]}"#)
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, server)
}

#[derive(Clone, Default)]
struct QuotaUpstreamState {
    billing_calls: Arc<AtomicUsize>,
    user_calls: Arc<AtomicUsize>,
    fail_billing: Arc<AtomicBool>,
}

async fn quota_models() -> Json<Value> {
    Json(json!({"data": [{"id": "grok-4.5", "owned_by": "xai"}]}))
}

async fn quota_user(State(state): State<QuotaUpstreamState>) -> Json<Value> {
    state.user_calls.fetch_add(1, Ordering::SeqCst);
    Json(json!({"userId": "upstream-user"}))
}

async fn quota_billing(State(state): State<QuotaUpstreamState>) -> (StatusCode, Json<Value>) {
    state.billing_calls.fetch_add(1, Ordering::SeqCst);
    if state.fail_billing.load(Ordering::SeqCst) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed"})),
        );
    }
    (
        StatusCode::OK,
        Json(
            json!({"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","start":"2026-07-16T02:27:51+00:00","end":"2026-07-23T02:27:51+00:00"},"creditUsagePercent":75.0,"onDemandCap":{"val":5000},"onDemandUsed":{"val":1250},"productUsage":[{"product":"GrokBuild","usagePercent":70.0}],"prepaidBalance":{"val":3000}}}),
        ),
    )
}

struct QuotaTestContext {
    upstream_state: QuotaUpstreamState,
    upstream_server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    repository: Arc<SqliteAccountRepository>,
    runtime: Arc<ProviderRuntimeCatalog>,
    manager: ProviderManager,
    auth: AuthService,
    owner: UserSummary,
    owner_session_token: SecretString,
    member: UserSummary,
    member_session_token: SecretString,
    account_id: AccountId,
    now: i64,
}

async fn quota_test_context() -> QuotaTestContext {
    let upstream_state = QuotaUpstreamState::default();
    let upstream = Router::new()
        .route("/v1/models", get(quota_models))
        .route("/v1/user", get(quota_user))
        .route("/v1/billing", get(quota_billing))
        .with_state(upstream_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind quota upstream");
    let address = listener.local_addr().expect("quota upstream address");
    let upstream_server = tokio::spawn(axum::serve(listener, upstream).into_future());
    let base_url = format!("http://{address}/v1");
    let repository = Arc::new(
        SqliteAccountRepository::in_memory()
            .await
            .expect("repository"),
    );
    let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
    runtime
        .register_driver(GrokDriver::for_test(base_url.clone()))
        .expect("register Grok driver");
    let auth = AuthService::new(repository.clone());
    let now = unix_timestamp();
    let owner_grant = auth
        .setup(
            "quota-owner".to_owned(),
            SecretString::from("secret1".to_owned()),
            now,
        )
        .await
        .expect("owner setup");
    let member = auth
        .create_user(
            &owner_grant.user,
            "quota-member".to_owned(),
            SecretString::from("secret2".to_owned()),
            now,
        )
        .await
        .expect("create member");
    let member_grant = auth
        .login(
            "quota-member".to_owned(),
            SecretString::from("secret2".to_owned()),
            now,
        )
        .await
        .expect("member login");
    let manager = ProviderManager::new(repository.clone(), runtime.clone());
    let credential_json = SecretString::from(
        serde_json::json!({
            "type": "xai",
            "auth_kind": "oauth",
            "access_token": "quota-token",
            "refresh_token": "quota-refresh",
            "token_endpoint": "https://auth.x.ai/oauth/token",
            "disabled": false
        })
        .to_string(),
    );
    let created = manager
        .create_credential_account(
            owner_grant.user.id.as_str(),
            CredentialProviderAccountInput {
                kind: ProviderKind::Grok,
                label: "shared Grok".to_owned(),
                group_label: "default".to_owned(),
                priority: 0,
                credential_json,
                visibility: provider_core::ProviderVisibility::Shared,
            },
            now,
        )
        .await
        .expect("create Grok account");

    QuotaTestContext {
        upstream_state,
        upstream_server,
        repository,
        runtime,
        manager,
        auth,
        owner: owner_grant.user,
        owner_session_token: owner_grant.session_token,
        member,
        member_session_token: member_grant.session_token,
        account_id: created.account.id,
        now,
    }
}

#[tokio::test]
async fn enforces_provider_ownership_without_returning_credentials() {
    let authorization = Arc::new(Mutex::new(Vec::<String>::new()));
    let upstream = Router::new()
        .route("/codex/models", get(captured_models))
        .with_state(authorization.clone());
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let upstream_server = tokio::spawn(axum::serve(upstream_listener, upstream).into_future());
    let (compatible_address, compatible_server) =
        spawn_compatible_tls_upstream(authorization.clone()).await;
    let compatible_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs("api.example.test", &[compatible_address])
        .build()
        .expect("compatible test client");

    let oauth_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind OAuth server");
    let oauth_address = oauth_listener.local_addr().expect("OAuth address");
    let oauth_base_url = format!("http://{oauth_address}");
    let discovery_body = serde_json::json!({
        "device_authorization_endpoint": format!("{oauth_base_url}/device"),
        "token_endpoint": format!("{oauth_base_url}/token")
    })
    .to_string();
    let oauth = Router::new()
        .route(
            "/discovery",
            get(move || {
                let body = discovery_body.clone();
                async move { body }
            }),
        )
        .route(
            "/device",
            post(|| async {
                r#"{"device_code":"device-1","user_code":"CODE-1","verification_uri":"https://accounts.x.ai/device","expires_in":600,"interval":60}"#
            }),
        )
        .route(
            "/token",
            post(|| async { r#"{"error":"authorization_pending"}"# }),
        );
    let oauth_server = tokio::spawn(axum::serve(oauth_listener, oauth).into_future());

    let repository = Arc::new(
        SqliteAccountRepository::in_memory()
            .await
            .expect("repository"),
    );
    let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
    runtime
        .register_driver(OpenAiCompatibleDriver::for_test(compatible_client))
        .expect("register driver");
    runtime
        .register_driver(GrokDriver::for_test_with_oauth(
            "http://127.0.0.1/unused",
            format!("{oauth_base_url}/discovery"),
        ))
        .expect("register Grok driver");
    runtime
        .register_driver(CodexDriver::for_test(
            &format!("http://{upstream_address}"),
            &oauth_base_url,
        ))
        .expect("register Codex driver");
    let auth = AuthService::new(repository.clone());
    let grant = auth
        .setup(
            "admin".to_owned(),
            SecretString::from("secret".to_owned()),
            unix_timestamp(),
        )
        .await
        .expect("initial setup");
    auth.create_user(
        &grant.user,
        "member".to_owned(),
        SecretString::from("secret2".to_owned()),
        unix_timestamp(),
    )
    .await
    .expect("create member");
    let member_grant = auth
        .login(
            "member".to_owned(),
            SecretString::from("secret2".to_owned()),
            unix_timestamp(),
        )
        .await
        .expect("member login");
    let session_token = grant.session_token.expose_secret().to_owned();
    let member_session_token = member_grant.session_token.expose_secret().to_owned();
    let api_keys = ApiKeyAuthenticator::load(repository.clone())
        .await
        .expect("API key index");
    let manager = ProviderManager::new(repository.clone(), runtime.clone());
    let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind management server");
    let address = listener.local_addr().expect("management address");
    let server = tokio::spawn(
        axum::serve(
            listener,
            router_with_management(service, manager, auth, api_keys),
        )
        .into_future(),
    );
    let client = reqwest::Client::new();
    let endpoint = format!("http://{address}/api/v1/providers");
    let codex_base_url = format!("http://{upstream_address}");
    let compatible_base_url = format!("https://api.example.test:{}", compatible_address.port());

    let exact_auth_body = padded_json(
        r#"{"username":""#,
        r#"","password":"secret"}"#,
        MAX_AUTH_BODY_BYTES,
    );
    let exact_auth = client
        .post(format!("http://{address}/api/v1/auth/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(exact_auth_body)
        .send()
        .await
        .expect("auth request at body limit");
    assert_eq!(exact_auth.status(), StatusCode::BAD_REQUEST);
    let oversized_auth_body = padded_json(
        r#"{"username":""#,
        r#"","password":"secret"}"#,
        MAX_AUTH_BODY_BYTES + 1,
    );
    let oversized_auth = client
        .post(format!("http://{address}/api/v1/auth/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(oversized_auth_body)
        .send()
        .await
        .expect("oversized auth request");
    assert_eq!(oversized_auth.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let compressed_auth = client
        .post(format!("http://{address}/api/v1/auth/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(r#"{"username":"admin","password":"secret"}"#)
        .send()
        .await
        .expect("compressed auth request");
    assert_eq!(compressed_auth.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let exact_management_body = padded_json(r#"{"label":""#, r#""}"#, MAX_MANAGEMENT_BODY_BYTES);
    let exact_management = client
        .patch(format!("{endpoint}/missing-account"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(exact_management_body)
        .send()
        .await
        .expect("management request at body limit");
    assert_eq!(exact_management.status(), StatusCode::NOT_FOUND);
    let oversized_management_body =
        padded_json(r#"{"label":""#, r#""}"#, MAX_MANAGEMENT_BODY_BYTES + 1);
    let oversized_management = client
        .patch(format!("{endpoint}/missing-account"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(oversized_management_body)
        .send()
        .await
        .expect("oversized management request");
    assert_eq!(oversized_management.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let malformed_management = client
        .patch(format!("{endpoint}/missing-account"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body("{")
        .send()
        .await
        .expect("malformed management request");
    assert_api_error(
        malformed_management,
        StatusCode::BAD_REQUEST,
        "request body must be valid JSON",
    )
    .await;

    let unknown_management_field = client
        .patch(format!("{endpoint}/missing-account"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"label":"updated","extra":true}"#)
        .send()
        .await
        .expect("management request with unknown field");
    assert_api_error(
        unknown_management_field,
        StatusCode::BAD_REQUEST,
        "request body must be valid JSON",
    )
    .await;

    let invalid_health_query = client
        .get(format!("{endpoint}/health?from_ms=invalid"))
        .headers(management_headers(&session_token))
        .send()
        .await
        .expect("invalid provider health query");
    assert_api_error(
        invalid_health_query,
        StatusCode::BAD_REQUEST,
        "query parameters are invalid",
    )
    .await;

    let compressed_management = client
        .patch(format!("{endpoint}/missing-account"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(r#"{"label":"compressed"}"#)
        .send()
        .await
        .expect("compressed management request");
    assert_eq!(
        compressed_management.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let codex_direct = client
        .post(&endpoint)
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "method": "direct",
                "provider": "codex",
                "label": "unsupported direct Codex",
                "group_label": "default",
                "base_url": codex_base_url,
                "api_key": "not-an-oauth-credential"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("reject direct Codex account");
    assert_eq!(codex_direct.status(), StatusCode::BAD_REQUEST);

    let compatible_credential = client
        .post(&endpoint)
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "method": "credential_json",
                "provider": "openai_compatible",
                "label": "unsupported compatible credential",
                "group_label": "default",
                "credential_json": {"type": "codex"}
            })
            .to_string(),
        )
        .send()
        .await
        .expect("reject compatible credential document");
    assert_eq!(compatible_credential.status(), StatusCode::BAD_REQUEST);

    let unsupported_oauth = client
        .post(format!("http://{address}/api/v1/oauth/sessions"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            r#"{"provider":"openai_compatible","label":"unsupported oauth","group_label":"default"}"#,
        )
        .send()
        .await
        .expect("reject unsupported OAuth provider");
    assert_eq!(unsupported_oauth.status(), StatusCode::BAD_REQUEST);

    let failed_discovery = client
        .post(&endpoint)
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "method": "direct",
                "provider": "openai_compatible",
                "label": "failed discovery",
                "group_label": "default",
                "base_url": format!("{compatible_base_url}/broken"),
                "api_key": "failed-discovery-key"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("fail account model discovery");
    assert_eq!(failed_discovery.status(), StatusCode::BAD_GATEWAY);
    let accounts_after_failure = client
        .get(&endpoint)
        .headers(management_headers(&session_token))
        .send()
        .await
        .expect("list accounts after failed creation");
    let accounts_after_failure: Value = serde_json::from_str(
        &accounts_after_failure
            .text()
            .await
            .expect("accounts after failed creation body"),
    )
    .expect("accounts after failed creation JSON");
    assert!(
        accounts_after_failure["data"]
            .as_array()
            .expect("provider accounts")
            .iter()
            .all(|account| account["label"] != "failed discovery"),
        "a failed model discovery must not leave a provider account"
    );

    let codex = client
        .post(&endpoint)
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "method": "credential_json",
                "provider": "codex",
                "label": "Codex OAuth",
                "group_label": "default",
                "credential_json": {
                    "type": "codex",
                    "auth_kind": "oauth",
                    "access_token": "codex-access",
                    "refresh_token": "codex-refresh",
                    "id_token": "e30.e30.sig",
                    "last_refreshed_at": 1
                }
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create Codex credential account");
    assert_eq!(codex.status(), StatusCode::CREATED);
    let codex_body = codex.text().await.expect("Codex account response");
    assert!(!codex_body.contains("codex-access"));
    assert!(!codex_body.contains("codex-refresh"));
    let codex_body: Value = serde_json::from_str(&codex_body).expect("Codex account JSON");
    let codex_account_id = codex_body["data"]["account"]["id"]
        .as_str()
        .expect("Codex account ID");
    assert_eq!(codex_body["data"]["account"]["provider"], "codex");
    assert_eq!(
        codex_body["data"]["account"]["config"],
        serde_json::json!({})
    );

    let codex_base_url_update = client
        .patch(format!("{endpoint}/{codex_account_id}"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"base_url":"https://example.invalid"}"#)
        .send()
        .await
        .expect("reject Codex base URL update");
    assert_eq!(codex_base_url_update.status(), StatusCode::BAD_REQUEST);

    let with_key = client
        .post(&endpoint)
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "method": "direct",
                "provider": "openai_compatible",
                "label": "with key",
                "group_label": "default",
                "base_url": compatible_base_url,
                "api_key": "do-not-return"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create keyed account");
    assert_eq!(with_key.status(), StatusCode::CREATED);
    let with_key_body = with_key.text().await.expect("keyed response");
    assert!(!with_key_body.contains("do-not-return"));
    let with_key_body: Value = serde_json::from_str(&with_key_body).expect("keyed response JSON");
    let private_account_id = with_key_body["data"]["account"]["id"]
        .as_str()
        .expect("private account ID")
        .to_owned();
    assert_eq!(
        with_key_body["data"]["account"]["owner_user_id"],
        grant.user.id.as_str()
    );
    assert_eq!(with_key_body["data"]["account"]["visibility"], "private");

    let empty_update_key = client
        .patch(format!("{endpoint}/{private_account_id}"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"api_key":"  "}"#)
        .send()
        .await
        .expect("reject empty compatible API key update");
    assert_eq!(empty_update_key.status(), StatusCode::BAD_REQUEST);

    let updated_compatible = client
        .patch(format!("{endpoint}/{private_account_id}"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "label": "updated compatible",
                "group_label": "default",
                "api_key": "replacement-provider-key"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("update compatible provider API key");
    assert_eq!(updated_compatible.status(), StatusCode::OK);
    let updated_compatible = updated_compatible
        .text()
        .await
        .expect("updated compatible response");
    assert!(!updated_compatible.contains("replacement-provider-key"));
    let updated_compatible: Value =
        serde_json::from_str(&updated_compatible).expect("updated compatible JSON");
    assert_eq!(updated_compatible["data"]["label"], "updated compatible");

    let refreshed_compatible = client
        .post(format!("{endpoint}/{private_account_id}/models/refresh"))
        .headers(management_headers(&session_token))
        .send()
        .await
        .expect("refresh compatible models with replacement API key");
    assert_eq!(refreshed_compatible.status(), StatusCode::OK);

    let empty_key = client
        .post(&endpoint)
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "method": "direct",
                "provider": "openai_compatible",
                "label": "empty key",
                "group_label": "default",
                "base_url": compatible_base_url,
                "api_key": ""
            })
            .to_string(),
        )
        .send()
        .await
        .expect("reject empty compatible API key");
    assert_eq!(empty_key.status(), StatusCode::BAD_REQUEST);

    let shared_account = client
        .post(&endpoint)
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "method": "direct",
                "provider": "openai_compatible",
                "label": "shared account",
                "group_label": "default",
                "base_url": compatible_base_url,
                "api_key": "shared-provider-key",
                "visibility": "shared"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create shared account");
    assert_eq!(shared_account.status(), StatusCode::CREATED);
    let shared_account_body: Value = serde_json::from_slice(
        &shared_account
            .bytes()
            .await
            .expect("shared account response body"),
    )
    .expect("shared account response JSON");
    let shared_account_id = shared_account_body["data"]["account"]["id"]
        .as_str()
        .expect("shared account ID")
        .to_owned();

    let member_create = client
        .post(&endpoint)
        .headers(management_headers(&member_session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "method": "direct",
                "provider": "openai_compatible",
                "label": "member private",
                "group_label": "default",
                "base_url": compatible_base_url,
                "api_key": "member-provider-key"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("reject member provider creation");
    assert_eq!(member_create.status(), StatusCode::FORBIDDEN);

    let member_accounts = client
        .get(&endpoint)
        .headers(management_headers(&member_session_token))
        .send()
        .await
        .expect("member provider list");
    assert_eq!(member_accounts.status(), StatusCode::OK);
    let member_accounts: Value = serde_json::from_slice(
        &member_accounts
            .bytes()
            .await
            .expect("member provider list body"),
    )
    .expect("member provider list JSON");
    let member_account_ids = member_accounts["data"]
        .as_array()
        .expect("member provider list")
        .iter()
        .filter_map(|account| account["id"].as_str())
        .collect::<Vec<_>>();
    assert!(!member_account_ids.contains(&private_account_id.as_str()));
    assert!(member_account_ids.contains(&shared_account_id.as_str()));

    let hidden_private = client
        .get(format!("{endpoint}/{private_account_id}"))
        .headers(management_headers(&member_session_token))
        .send()
        .await
        .expect("hidden private provider");
    assert_eq!(hidden_private.status(), StatusCode::NOT_FOUND);

    let visible_shared = client
        .get(format!("{endpoint}/{shared_account_id}"))
        .headers(management_headers(&member_session_token))
        .send()
        .await
        .expect("visible shared provider");
    assert_eq!(visible_shared.status(), StatusCode::OK);

    let shared_models = client
        .get(format!("{endpoint}/{shared_account_id}/models"))
        .headers(management_headers(&member_session_token))
        .send()
        .await
        .expect("shared models");
    assert_eq!(shared_models.status(), StatusCode::OK);

    let shared_update = client
        .patch(format!("{endpoint}/{shared_account_id}"))
        .headers(management_headers(&member_session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"label":"not allowed"}"#)
        .send()
        .await
        .expect("shared provider update");
    assert_eq!(shared_update.status(), StatusCode::FORBIDDEN);

    let shared_model_update = client
        .patch(format!("{endpoint}/{shared_account_id}/models"))
        .headers(management_headers(&member_session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            r#"{"upstream_model":"model-a","alias":"no","enabled":true,"input_modalities":null,"pricing_changed":false}"#,
        )
        .send()
        .await
        .expect("shared model update");
    assert_eq!(shared_model_update.status(), StatusCode::FORBIDDEN);

    let oauth_session = client
        .post(format!("http://{address}/api/v1/oauth/sessions"))
        .headers(management_headers(&session_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"provider":"grok","label":"admin oauth","group_label":"default","visibility":"shared"}"#)
        .send()
        .await
        .expect("start admin OAuth");
    assert_eq!(oauth_session.status(), StatusCode::CREATED);
    let oauth_session: Value =
        serde_json::from_slice(&oauth_session.bytes().await.expect("OAuth response body"))
            .expect("OAuth response JSON");
    assert_eq!(
        oauth_session["data"]["owner_user_id"],
        grant.user.id.as_str()
    );
    assert_eq!(oauth_session["data"]["visibility"], "shared");
    let oauth_session_id = oauth_session["data"]["id"]
        .as_str()
        .expect("OAuth session ID");
    let oauth_endpoint = format!("http://{address}/api/v1/oauth/sessions/{oauth_session_id}");

    let forbidden_oauth_read = client
        .get(&oauth_endpoint)
        .headers(management_headers(&member_session_token))
        .send()
        .await
        .expect("reject member OAuth read");
    assert_eq!(forbidden_oauth_read.status(), StatusCode::FORBIDDEN);

    let visible_oauth = client
        .get(&oauth_endpoint)
        .headers(management_headers(&session_token))
        .send()
        .await
        .expect("admin OAuth session");
    assert_eq!(visible_oauth.status(), StatusCode::OK);

    let forbidden_oauth_cancel = client
        .delete(&oauth_endpoint)
        .headers(management_headers(&member_session_token))
        .send()
        .await
        .expect("reject member OAuth cancellation");
    assert_eq!(forbidden_oauth_cancel.status(), StatusCode::FORBIDDEN);

    let cancelled_oauth = client
        .delete(&oauth_endpoint)
        .headers(management_headers(&session_token))
        .send()
        .await
        .expect("cancel admin OAuth session");
    assert_eq!(cancelled_oauth.status(), StatusCode::OK);

    server.abort();
    upstream_server.abort();
    compatible_server.abort();
    oauth_server.abort();
    runtime.shutdown();
    assert_eq!(
        authorization.lock().expect("authorization lock").as_slice(),
        [
            "Bearer codex-access",
            "Bearer do-not-return",
            "Bearer replacement-provider-key",
            "Bearer replacement-provider-key",
            "Bearer shared-provider-key",
        ]
    );
}

#[tokio::test]
async fn quota_http_filters_shared_billing_and_forces_refresh() {
    let context = quota_test_context().await;
    let upstream_state = context.upstream_state.clone();
    let repository = context.repository.clone();
    let runtime = context.runtime.clone();
    let manager = context.manager.clone();
    let auth = context.auth.clone();
    let owner = context.owner.clone();
    let owner_session_token = context.owner_session_token.clone();
    let member = context.member.clone();
    let member_session_token = context.member_session_token.clone();
    let account_id = context.account_id.clone();
    let now = context.now;

    let first = manager
        .quota(member.id.as_str(), &account_id, now)
        .await
        .expect("member quota");
    assert_eq!(first.support, ProviderQuotaSupport::Supported);
    assert_eq!(first.freshness, Some(ProviderQuotaFreshness::Fresh));
    assert_eq!(
        first
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.groups.len()),
        Some(1)
    );
    assert_eq!(
        first
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.groups.first())
            .map(|group| group.key.as_str()),
        Some("grok")
    );
    let owner_summary = manager
        .get_account(owner.id.as_str(), &account_id)
        .await
        .expect("owner account");
    let owner_quota = manager
        .cached_quota(owner.id.as_str(), &owner_summary, now)
        .await;
    assert_eq!(
        owner_quota
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.groups.len()),
        Some(2)
    );
    assert_eq!(upstream_state.user_calls.load(Ordering::SeqCst), 2);
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);

    let api_keys = ApiKeyAuthenticator::load(repository.clone())
        .await
        .expect("API key index");
    let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
    let management_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind quota management server");
    let management_address = management_listener
        .local_addr()
        .expect("quota management address");
    let management_server = tokio::spawn(
        axum::serve(
            management_listener,
            router_with_management(service, manager.clone(), auth, api_keys),
        )
        .into_future(),
    );
    let client = reqwest::Client::new();
    let session_token = member_session_token.expose_secret();
    let owner_session_token = owner_session_token.expose_secret();
    let endpoint = format!("http://{management_address}/api/v1/providers");
    let list_response = client
        .get(&endpoint)
        .headers(management_headers(session_token))
        .send()
        .await
        .expect("quota provider list");
    let list_response: Value = serde_json::from_slice(
        &list_response
            .bytes()
            .await
            .expect("quota provider list body"),
    )
    .expect("quota provider list JSON");
    assert_eq!(list_response["data"][0]["quota"]["freshness"], "fresh");
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);
    let quota_response = client
        .get(format!("{endpoint}/{account_id}/quota"))
        .headers(management_headers(session_token))
        .send()
        .await
        .expect("quota endpoint");
    let quota_response: Value =
        serde_json::from_slice(&quota_response.bytes().await.expect("quota endpoint body"))
            .expect("quota endpoint JSON");
    assert_eq!(quota_response["data"]["support"], "supported");
    assert_eq!(quota_response["data"]["freshness"], "fresh");
    assert_eq!(
        quota_response["data"]["snapshot"]["groups"][0]["metrics"][0]["breakdown"][0]["key"],
        "grok_build"
    );
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);
    let forbidden_refresh = client
        .post(format!("{endpoint}/{account_id}/quota/refresh"))
        .headers(management_headers(session_token))
        .send()
        .await
        .expect("reject member quota refresh");
    assert_eq!(forbidden_refresh.status(), StatusCode::FORBIDDEN);
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);
    let refresh_response = client
        .post(format!("{endpoint}/{account_id}/quota/refresh"))
        .headers(management_headers(owner_session_token))
        .send()
        .await
        .expect("refresh quota endpoint");
    assert_eq!(refresh_response.status(), StatusCode::OK);
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 2);
    management_server.abort();
    context.upstream_server.abort();
    runtime.shutdown();
}

#[tokio::test]
async fn quota_cache_handles_singleflight_backoff_and_credential_replacement() {
    let context = quota_test_context().await;
    let upstream_state = context.upstream_state.clone();
    let repository = context.repository.clone();
    let runtime = context.runtime.clone();
    let manager = context.manager.clone();
    let owner = context.owner.clone();
    let member = context.member.clone();
    let account_id = context.account_id.clone();
    let now = context.now;

    manager
        .quota(member.id.as_str(), &account_id, now)
        .await
        .expect("initial quota");
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 1);

    let (first_refresh, second_refresh) = tokio::join!(
        manager.refresh_quota(member.id.as_str(), &account_id, now + 31),
        manager.refresh_quota(member.id.as_str(), &account_id, now + 31),
    );
    first_refresh.expect("first forced member refresh");
    second_refresh.expect("second forced member refresh");
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 2);

    manager
        .set_account_enabled(owner.id.as_str(), &account_id, false, now + 32)
        .await
        .expect("disable account");
    let disabled = manager
        .quota(member.id.as_str(), &account_id, now + 62)
        .await
        .expect("disabled quota");
    assert_eq!(disabled.freshness, Some(ProviderQuotaFreshness::Fresh));
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 3);
    assert!(
        !manager
            .get_account(owner.id.as_str(), &account_id)
            .await
            .expect("disabled account")
            .enabled
    );

    upstream_state.fail_billing.store(true, Ordering::SeqCst);
    let stale = manager
        .quota(member.id.as_str(), &account_id, now + 93)
        .await
        .expect("stale quota");
    assert_eq!(stale.freshness, Some(ProviderQuotaFreshness::Stale));
    assert_eq!(stale.last_error, Some(ProviderQuotaErrorKind::Upstream));
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 4);
    let backed_off = manager
        .refresh_quota(member.id.as_str(), &account_id, now + 94)
        .await
        .expect("quota failure backoff");
    assert_eq!(backed_off.freshness, Some(ProviderQuotaFreshness::Stale));
    assert_eq!(
        backed_off.last_error,
        Some(ProviderQuotaErrorKind::Upstream)
    );
    assert_eq!(upstream_state.billing_calls.load(Ordering::SeqCst), 4);

    let stored = repository
        .load_provider_account(&account_id)
        .await
        .expect("load account")
        .expect("stored account");
    manager
        .update_credential(
            owner.id.as_str(),
            &account_id,
            ProviderCredentialReplacement {
                kind: CredentialKind::Oauth,
                format_version: stored.credential.format_version,
                credential_json: SecretString::from(
                    serde_json::json!({
                        "type": "xai",
                        "auth_kind": "oauth",
                        "access_token": "replacement-token",
                        "refresh_token": "replacement-refresh",
                        "upstream_user_id": "replacement-user",
                        "token_endpoint": "https://auth.x.ai/oauth/token",
                        "disabled": false
                    })
                    .to_string(),
                ),
                expires_at: None,
                last_refreshed_at: None,
                updated_at: now + 94,
            },
        )
        .await
        .expect("replace credential");
    let listed = manager
        .list_accounts(member.id.as_str())
        .await
        .expect("member account list");
    let summary = listed
        .iter()
        .find(|account| account.id == account_id)
        .expect("shared account summary");
    let cached = manager
        .cached_quota(member.id.as_str(), summary, now + 94)
        .await;
    assert_eq!(cached.support, ProviderQuotaSupport::Supported);
    assert!(cached.snapshot.is_none());
    context.upstream_server.abort();
    runtime.shutdown();
}
