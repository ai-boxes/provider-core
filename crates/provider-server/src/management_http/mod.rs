mod accounts;
mod health;
mod models;
mod oauth;
mod quota;
mod shared;

use axum::{
    Router,
    routing::{get, post, put},
};
use provider_management::ProviderManager;

use accounts::{
    create_account, delete_account, get_account, list_accounts, set_account_enabled, update_account,
};
use health::list_provider_health;
use models::{list_models, refresh_models, update_model};
use oauth::{cancel_oauth_session, get_oauth_session, start_oauth_session};
use quota::{get_quota, refresh_quota};

#[cfg(test)]
use accounts::SetEnabledRequest;
#[cfg(test)]
use health::ProviderHealthParams;
#[cfg(test)]
use models::{ModelPricingPatch, UpdateModelRequest, model_is_visible, updated_pricing};
#[cfg(test)]
use shared::{require_super_admin, unix_timestamp};

#[derive(Clone)]
struct ManagementState {
    manager: ProviderManager,
    usage: Option<crate::UsageServices>,
}

pub(crate) fn router(manager: ProviderManager, usage: Option<crate::UsageServices>) -> Router {
    Router::new()
        .route("/api/v1/providers", get(list_accounts).post(create_account))
        .route("/api/v1/providers/health", get(list_provider_health))
        .route(
            "/api/v1/providers/{account_id}",
            get(get_account)
                .patch(update_account)
                .delete(delete_account),
        )
        .route(
            "/api/v1/providers/{account_id}/enabled",
            put(set_account_enabled),
        )
        .route(
            "/api/v1/providers/{account_id}/models",
            get(list_models).patch(update_model),
        )
        .route(
            "/api/v1/providers/{account_id}/models/refresh",
            post(refresh_models),
        )
        .route("/api/v1/providers/{account_id}/quota", get(get_quota))
        .route(
            "/api/v1/providers/{account_id}/quota/refresh",
            post(refresh_quota),
        )
        .route("/api/v1/oauth/sessions", post(start_oauth_session))
        .route(
            "/api/v1/oauth/sessions/{session_id}",
            get(get_oauth_session).delete(cancel_oauth_session),
        )
        .with_state(ManagementState { manager, usage })
}

#[cfg(test)]
mod tests;
