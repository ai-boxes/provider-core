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
    issue_api_key, issue_registration_code, issue_session_tokens, rotate_session_tokens,
    validate_password, verify_password,
};
pub use model::{
    ApiKeyId, ApiKeyIdError, ApiKeySummary, CreatedApiKey, NewApiKey, NewRegistrationCode,
    NewSession, NewUser, SessionId, SessionIdError, StoredApiKey, StoredSession, StoredUser,
    USD_ATOM_SCALE, UserId, UserIdError, UserRole, UserRoleError, UserSummary, add_atoms, atoms_ge,
    format_usd_atoms, parse_quota_limit_usd,
};
pub use repository::{
    AuthRepository, AuthRepositoryError, InitialUserCreateOutcome, RefreshSessionOutcome,
    RegisterUserOutcome,
};
pub use service::{
    ApiKeyAuthenticator, ApiKeyQuotaLease, AuthError, AuthService, AuthenticatedApiKey,
    AuthenticatedSession, CreatedRegistrationCode, REGISTRATION_CODE_TTL_SECONDS, SessionGrant,
};
