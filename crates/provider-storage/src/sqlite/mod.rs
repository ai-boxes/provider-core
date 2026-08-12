use std::{path::Path, str::FromStr, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use provider_auth::{
    ApiKeyId, AuthRepository, AuthRepositoryError, InitialUserCreateOutcome, NewApiKey,
    NewRegistrationCode, NewSession, NewUser, QuotaAdmissionOutcome, RegisterUserOutcome,
    SessionId, StoredApiKey, StoredApiKeyUpdate, StoredSession, StoredUser, UserId, UserRole,
    UserSummary, atoms_ge,
};
#[cfg(test)]
use provider_core::ProviderModelPricingTier;
use provider_core::{
    AccountAuthState, AccountId, AccountRepository, AccountRepositoryError, CredentialKind,
    CredentialUpdate, CredentialWriteOutcome, DiscoveredProviderModel, NewProviderAccount,
    ProviderAccountCreateOutcome, ProviderAccountSummary, ProviderAccountUpdate, ProviderKind,
    ProviderManagementRepository, ProviderModelOverride, ProviderModelPricing,
    ProviderModelPricingRecord, ProviderModelPricingSource, ProviderSnapshot,
    ProviderSnapshotWriteOutcome, ProviderVisibility, StoredCredential, StoredProviderAccount,
    StoredProviderModel,
};
use provider_usage::{component_prices_from_model_pricing, context_price_tiers_from_model_pricing};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{
    ConnectOptions, Row, SqlitePool,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow},
};

mod account_repository;
mod auth;
mod connection;
mod credential_cipher;
mod provider_management;
mod row_mapping;

#[cfg(test)]
mod tests;

use credential_cipher::CredentialCipher;
use row_mapping::*;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct SqliteAccountRepository {
    pool: SqlitePool,
    credential_cipher: CredentialCipher,
}
