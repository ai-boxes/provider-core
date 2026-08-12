use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::{
        Query,
        rejection::{JsonRejection, QueryRejection},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use provider_auth::{AuthenticatedSession, UserRole};
use provider_core::AccountId;
use provider_management::{ModelCatalogError, ProviderManagerError};
use serde_json::{Value, json};

pub(super) fn require_super_admin(session: &AuthenticatedSession) -> Result<(), ApiError> {
    if session.user.role == UserRole::SuperAdmin {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

pub(super) fn parse_account_id(value: &str) -> Result<AccountId, ApiError> {
    AccountId::new(value).map_err(|_| ApiError::invalid_request("invalid provider account ID"))
}

pub(super) fn data(value: Value) -> Json<Value> {
    Json(json!({ "data": value }))
}

pub(super) fn json_request<T>(request: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    request.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::payload_too_large()
        } else {
            ApiError::invalid_request("request body must be valid JSON")
        }
    })
}

pub(super) fn query_request<T>(request: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    request
        .map(|Query(request)| request)
        .map_err(|_| ApiError::invalid_request("query parameters are invalid"))
}

pub(super) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after unix epoch")
        .as_secs()
        .try_into()
        .expect("unix timestamp must fit i64")
}

pub(super) struct ApiError {
    pub(super) status: StatusCode,
    error_type: &'static str,
    message: String,
}

impl ApiError {
    pub(super) fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error_type: "invalid_request_error",
            message: message.into(),
        }
    }

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            error_type: "invalid_request_error",
            message: "request body is too large".to_owned(),
        }
    }

    pub(super) fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error_type: "not_found_error",
            message: "resource was not found".to_owned(),
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error_type: "forbidden_error",
            message: "super_admin role is required".to_owned(),
        }
    }

    pub(super) fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error_type: "api_error",
            message: "internal server error".to_owned(),
        }
    }
}

impl From<ProviderManagerError> for ApiError {
    fn from(error: ProviderManagerError) -> Self {
        match error {
            ProviderManagerError::InvalidInput(message) => Self::invalid_request(message),
            ProviderManagerError::NotFound => Self::not_found(),
            ProviderManagerError::Forbidden => Self {
                status: StatusCode::FORBIDDEN,
                error_type: "forbidden_error",
                message: error.to_string(),
            },
            ProviderManagerError::Conflict => Self {
                status: StatusCode::CONFLICT,
                error_type: "conflict_error",
                message: error.to_string(),
            },
            ProviderManagerError::Control(_) => Self {
                status: StatusCode::BAD_REQUEST,
                error_type: "invalid_request_error",
                message: error.to_string(),
            },
            ProviderManagerError::OAuthStart(_) => Self {
                status: StatusCode::BAD_GATEWAY,
                error_type: "upstream_error",
                message: error.to_string(),
            },
            ProviderManagerError::ModelCatalog(ModelCatalogError::Discovery(_)) => Self {
                status: StatusCode::BAD_GATEWAY,
                error_type: "upstream_error",
                message: error.to_string(),
            },
            ProviderManagerError::Repository(_) | ProviderManagerError::MissingOwner => {
                Self::internal()
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": { "type": self.error_type, "message": self.message }
            })),
        )
            .into_response()
    }
}
