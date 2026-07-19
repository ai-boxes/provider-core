//! User authentication and API key domain services.

#![forbid(unsafe_code)]

mod credentials;
mod model;
mod repository;
mod service;

pub use credentials::{
    ABSOLUTE_SESSION_TTL_SECONDS, ACCESS_TOKEN_TTL_SECONDS, API_KEY_MAX_BYTES,
    API_KEY_MIN_CHARACTERS, AccessRefreshTokens, CredentialError, IssuedSecret, PASSWORD_MAX_BYTES,
    PASSWORD_MIN_CHARACTERS, REFRESH_TOKEN_TTL_SECONDS, digest_secret, hash_password,
    issue_api_key, issue_session_tokens, rotate_session_tokens, validate_password, verify_password,
};
pub use model::{
    ApiKeyId, ApiKeyIdError, ApiKeySummary, CreatedApiKey, NewApiKey, NewSession, NewUser,
    SessionId, SessionIdError, StoredApiKey, StoredSession, StoredUser, UserId, UserIdError,
    UserRole, UserRoleError, UserSummary,
};
pub use repository::{
    AuthRepository, AuthRepositoryError, InitialUserCreateOutcome, RefreshSessionOutcome,
};
pub use service::{
    ApiKeyAuthenticator, AuthError, AuthService, AuthenticatedApiKey, AuthenticatedSession,
    SessionGrant,
};
