//! User authentication and API key domain services.

#![forbid(unsafe_code)]

mod credentials;
mod model;
mod repository;
mod service;

pub use credentials::{
    CredentialError, IssuedSecret, IssuedSession, PASSWORD_MAX_BYTES, PASSWORD_MIN_CHARACTERS,
    SESSION_TTL_SECONDS, digest_secret, hash_password, issue_api_key, issue_registration_code,
    issue_session, validate_password, verify_password,
};
pub use model::{
    ApiKeyId, ApiKeyIdError, ApiKeyPatch, ApiKeySummary, CreatedApiKey, NewApiKey,
    NewRegistrationCode, NewSession, NewUser, SessionId, SessionIdError, StoredApiKey,
    StoredApiKeyUpdate, StoredSession, StoredUser, USD_ATOM_SCALE, UsdAtomsError, UserId,
    UserIdError, UserRole, UserRoleError, UserSummary, add_atoms, atoms_ge, format_usd_atoms,
    parse_quota_limit_usd,
};
pub use repository::{
    AuthRepository, AuthRepositoryError, InitialUserCreateOutcome, QuotaAdmissionOutcome,
    RegisterUserOutcome, UserUpdateOutcome,
};
pub use service::{
    ApiKeyAuthenticator, AuthError, AuthService, AuthenticatedApiKey, AuthenticatedSession,
    CreateApiKeyInput, CreatedRegistrationCode, REGISTRATION_CODE_TTL_SECONDS, SessionGrant,
};
