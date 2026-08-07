use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, PoisonError, RwLock},
};

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::{
    ApiKeyId, ApiKeySummary, AuthRepository, AuthRepositoryError, CreatedApiKey, CredentialError,
    InitialUserCreateOutcome, NewApiKey, NewRegistrationCode, NewSession, NewUser,
    RefreshSessionOutcome, RegisterUserOutcome, SessionId, StoredApiKey, UserId, UserRole,
    UserSummary, add_atoms, atoms_ge, digest_secret, hash_password, issue_api_key,
    issue_registration_code, issue_session_tokens, parse_quota_limit_usd, rotate_session_tokens,
    verify_password,
};

pub const REGISTRATION_CODE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Clone)]
pub struct AuthService {
    repository: Arc<dyn AuthRepository>,
}

pub struct SessionGrant {
    pub user: UserSummary,
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
}

pub struct CreatedRegistrationCode {
    pub code: SecretString,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSession {
    pub session_id: SessionId,
    pub user: UserSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedApiKey {
    pub key_id: ApiKeyId,
    pub owner_user_id: UserId,
    pub label: String,
    pub group_label: String,
    pub quota_limit_atoms: Option<String>,
}

impl AuthService {
    #[must_use]
    pub fn new(repository: Arc<dyn AuthRepository>) -> Self {
        Self { repository }
    }

    pub async fn setup_required(&self) -> Result<bool, AuthError> {
        Ok(self.repository.setup_required().await?)
    }

    pub async fn setup(
        &self,
        username: String,
        password: SecretString,
        now: i64,
    ) -> Result<SessionGrant, AuthError> {
        let username = normalize_username(username)?;
        let password_hash = password_hash(password).await?;
        let user_id = UserId::random();
        let user = NewUser {
            id: user_id.clone(),
            username: username.clone(),
            password_hash,
            role: UserRole::SuperAdmin,
            enabled: true,
            created_at: now,
        };
        let user_summary = UserSummary {
            id: user_id.clone(),
            username,
            role: UserRole::SuperAdmin,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        let (session, grant) = new_session_grant(user_summary, now)?;
        if self.repository.create_initial_user(user, session).await?
            != InitialUserCreateOutcome::Created
        {
            return Err(AuthError::AlreadyConfigured);
        }
        Ok(grant)
    }

    pub async fn login(
        &self,
        username: String,
        password: SecretString,
        now: i64,
    ) -> Result<SessionGrant, AuthError> {
        let username = normalize_username(username)?;
        let Some(user) = self.repository.load_user_by_username(&username).await? else {
            consume_missing_user_password(password).await;
            return Err(AuthError::InvalidCredentials);
        };
        let password_valid = verify_password_async(password, user.password_hash.clone()).await?;
        if !password_valid || !user.enabled {
            return Err(AuthError::InvalidCredentials);
        }
        self.create_session(user_summary(&user), now).await
    }

    pub async fn authenticate_access(
        &self,
        access_token: &str,
        now: i64,
    ) -> Result<AuthenticatedSession, AuthError> {
        let digest = digest_secret(access_token);
        let session = self
            .repository
            .load_session_by_access_hash(&digest)
            .await?
            .ok_or(AuthError::InvalidAccessToken)?;
        if session.revoked_at.is_some() || session.access_expires_at <= now || !session.user.enabled
        {
            return Err(AuthError::InvalidAccessToken);
        }
        Ok(AuthenticatedSession {
            session_id: session.id,
            user: session.user,
        })
    }

    pub async fn refresh(&self, refresh_token: &str, now: i64) -> Result<SessionGrant, AuthError> {
        let digest = digest_secret(refresh_token);
        let session = self
            .repository
            .load_session_by_refresh_hash(&digest)
            .await?
            .ok_or(AuthError::InvalidRefreshToken)?;
        if session.revoked_at.is_some()
            || session.refresh_expires_at <= now
            || session.absolute_expires_at <= now
            || !session.user.enabled
        {
            return Err(AuthError::InvalidRefreshToken);
        }
        let tokens = rotate_session_tokens(now, session.absolute_expires_at)?;
        let outcome = self
            .repository
            .rotate_session(
                &digest,
                tokens.access.digest,
                tokens.refresh.digest,
                tokens.access_expires_at,
                tokens.refresh_expires_at,
                now,
            )
            .await?;
        if outcome != RefreshSessionOutcome::Updated {
            return Err(AuthError::InvalidRefreshToken);
        }
        Ok(SessionGrant {
            user: session.user,
            access_token: tokens.access.secret,
            refresh_token: tokens.refresh.secret,
            access_expires_at: tokens.access_expires_at,
            refresh_expires_at: tokens.refresh_expires_at,
        })
    }

    pub async fn logout(&self, access_token: &str, now: i64) -> Result<(), AuthError> {
        let session = self.authenticate_access(access_token, now).await?;
        self.logout_session(&session.session_id, now).await
    }

    pub async fn logout_session(&self, session_id: &SessionId, now: i64) -> Result<(), AuthError> {
        if !self.repository.revoke_session(session_id, now).await? {
            return Err(AuthError::InvalidAccessToken);
        }
        Ok(())
    }

    pub async fn list_users(&self, actor: &UserSummary) -> Result<Vec<UserSummary>, AuthError> {
        require_super_admin(actor)?;
        Ok(self.repository.list_users().await?)
    }

    pub async fn create_user(
        &self,
        actor: &UserSummary,
        username: String,
        password: SecretString,
        now: i64,
    ) -> Result<UserSummary, AuthError> {
        require_super_admin(actor)?;
        let user = new_standard_user(username, password, now).await?;
        if !self.repository.create_user(user.clone()).await? {
            return Err(AuthError::Conflict);
        }
        Ok(new_user_summary(user))
    }

    pub async fn create_registration_code(
        &self,
        actor: &UserSummary,
        now: i64,
    ) -> Result<CreatedRegistrationCode, AuthError> {
        require_super_admin(actor)?;
        let issued = issue_registration_code()?;
        let expires_at = now
            .checked_add(REGISTRATION_CODE_TTL_SECONDS)
            .ok_or(CredentialError::TimestampOutOfRange)?;
        self.repository
            .create_registration_code(NewRegistrationCode {
                code_hash: issued.digest,
                expires_at,
            })
            .await?;
        Ok(CreatedRegistrationCode {
            code: issued.secret,
            expires_at,
        })
    }

    pub async fn register_user(
        &self,
        code: &str,
        username: String,
        password: SecretString,
        now: i64,
    ) -> Result<SessionGrant, AuthError> {
        let code = normalize_registration_code(code)?;
        let code_hash = digest_secret(code);
        if !self
            .repository
            .registration_code_valid(&code_hash, now)
            .await?
        {
            return Err(AuthError::InvalidRegistrationCode);
        }
        let user = new_standard_user(username, password, now).await?;
        let (session, grant) = new_session_grant(new_user_summary(user.clone()), now)?;
        match self
            .repository
            .register_user(&code_hash, user, session, now)
            .await?
        {
            RegisterUserOutcome::Created => Ok(grant),
            RegisterUserOutcome::InvalidCode => Err(AuthError::InvalidRegistrationCode),
            RegisterUserOutcome::Conflict => Err(AuthError::Conflict),
        }
    }

    pub async fn set_user_enabled(
        &self,
        actor: &UserSummary,
        user_id: &UserId,
        enabled: bool,
        now: i64,
    ) -> Result<UserSummary, AuthError> {
        require_super_admin(actor)?;
        if !enabled && actor.id == *user_id {
            return Err(AuthError::Forbidden);
        }
        if !self
            .repository
            .set_user_enabled(user_id, enabled, now)
            .await?
        {
            return Err(AuthError::NotFound);
        }
        let user = self
            .repository
            .load_user(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        Ok(user_summary(&user))
    }

    pub async fn reset_user_password(
        &self,
        actor: &UserSummary,
        user_id: &UserId,
        password: SecretString,
        now: i64,
    ) -> Result<UserSummary, AuthError> {
        require_super_admin(actor)?;
        let password_hash = password_hash(password).await?;
        if !self
            .repository
            .update_user_password(user_id, password_hash, now)
            .await?
        {
            return Err(AuthError::NotFound);
        }
        self.repository.revoke_user_sessions(user_id, now).await?;
        let user = self
            .repository
            .load_user(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        Ok(user_summary(&user))
    }

    async fn create_session(&self, user: UserSummary, now: i64) -> Result<SessionGrant, AuthError> {
        let (session, grant) = new_session_grant(user, now)?;
        self.repository.create_session(session).await?;
        Ok(grant)
    }
}

fn new_session_grant(user: UserSummary, now: i64) -> Result<(NewSession, SessionGrant), AuthError> {
    let tokens = issue_session_tokens(now)?;
    let session = NewSession {
        id: SessionId::random(),
        user_id: user.id.clone(),
        access_token_hash: tokens.access.digest,
        refresh_token_hash: tokens.refresh.digest,
        access_expires_at: tokens.access_expires_at,
        refresh_expires_at: tokens.refresh_expires_at,
        absolute_expires_at: tokens.absolute_expires_at,
        created_at: now,
    };
    let grant = SessionGrant {
        user,
        access_token: tokens.access.secret,
        refresh_token: tokens.refresh.secret,
        access_expires_at: tokens.access_expires_at,
        refresh_expires_at: tokens.refresh_expires_at,
    };
    Ok((session, grant))
}

#[derive(Clone)]
pub struct ApiKeyAuthenticator {
    repository: Arc<dyn AuthRepository>,
    active: Arc<RwLock<HashMap<[u8; 32], ActiveApiKey>>>,
    mutation: Arc<Mutex<()>>,
    quota_spent: Arc<RwLock<HashMap<ApiKeyId, QuotaSpend>>>,
    quota_gates: Arc<StdMutex<HashMap<ApiKeyId, Arc<Mutex<()>>>>>,
}

/// Holds the single in-flight request slot for a quota-limited API key.
pub struct ApiKeyQuotaLease {
    _guard: Option<OwnedMutexGuard<()>>,
}

#[derive(Clone)]
struct ActiveApiKey {
    id: ApiKeyId,
    owner_user_id: UserId,
    label: String,
    group_label: String,
    quota_limit_atoms: Option<String>,
    expires_at: Option<i64>,
}

#[derive(Clone)]
enum QuotaSpend {
    Known(String),
    Unavailable,
}

impl ApiKeyAuthenticator {
    pub async fn load(repository: Arc<dyn AuthRepository>) -> Result<Self, AuthError> {
        let keys = repository.load_active_api_keys().await?;
        let quota_spent = keys
            .iter()
            .filter(|key| key.quota_limit_atoms.is_some())
            .map(|key| (key.id.clone(), quota_spend(&key.spent_atoms)))
            .collect();
        Ok(Self {
            repository,
            active: Arc::new(RwLock::new(active_key_map(keys))),
            mutation: Arc::new(Mutex::new(())),
            quota_spent: Arc::new(RwLock::new(quota_spent)),
            quota_gates: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    pub fn authenticate(&self, key: &str, now: i64) -> Result<AuthenticatedApiKey, AuthError> {
        let digest = digest_secret(key);
        let active = self.active.read().unwrap_or_else(PoisonError::into_inner);
        let key = active.get(&digest).ok_or(AuthError::InvalidApiKey)?;
        if key.expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(AuthError::InvalidApiKey);
        }
        Ok(AuthenticatedApiKey {
            key_id: key.id.clone(),
            owner_user_id: key.owner_user_id.clone(),
            label: key.label.clone(),
            group_label: key.group_label.clone(),
            quota_limit_atoms: key.quota_limit_atoms.clone(),
        })
    }

    pub async fn create(
        &self,
        owner_user_id: &UserId,
        group_label: String,
        label: String,
        custom: Option<SecretString>,
        expires_at: Option<i64>,
        quota_limit_usd: Option<String>,
        now: i64,
    ) -> Result<CreatedApiKey, AuthError> {
        let label = normalize_label(label)?;
        let group_label = normalize_group_label(group_label)?;
        if expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(AuthError::InvalidExpiry);
        }
        let quota_limit_atoms = match quota_limit_usd {
            None => None,
            Some(value) => {
                Some(parse_quota_limit_usd(&value).map_err(|_| AuthError::InvalidQuotaLimit)?)
            }
        };
        let issued = issue_api_key(custom)?;
        let key = NewApiKey {
            id: ApiKeyId::random(),
            owner_user_id: owner_user_id.clone(),
            group_label: group_label.clone(),
            label,
            key: issued.secret.clone(),
            enabled: true,
            expires_at,
            quota_limit_atoms: quota_limit_atoms.clone(),
            created_at: now,
        };
        let summary = ApiKeySummary {
            id: key.id.clone(),
            owner_user_id: key.owner_user_id.clone(),
            group_label: group_label.clone(),
            label: key.label.clone(),
            key: mask_api_key(key.key.expose_secret()),
            enabled: true,
            expires_at,
            quota_limit_atoms: quota_limit_atoms.clone(),
            spent_atoms: "0".to_owned(),
            last_used_at: None,
            created_at: now,
            updated_at: now,
        };
        let _mutation = self.mutation.lock().await;
        let account_ids = self
            .repository
            .list_visible_account_ids_by_group_label(owner_user_id, &group_label)
            .await?;
        if account_ids.is_empty() {
            return Err(AuthError::GroupNotFound);
        }
        if !self.repository.create_api_key(key.clone()).await? {
            return Err(AuthError::Conflict);
        }
        if quota_limit_atoms.is_some() {
            self.quota_spent
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(summary.id.clone(), QuotaSpend::Known("0".to_owned()));
        }
        self.active
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                issued.digest,
                ActiveApiKey {
                    id: key.id,
                    owner_user_id: key.owner_user_id,
                    label: key.label,
                    group_label,
                    quota_limit_atoms: key.quota_limit_atoms,
                    expires_at: key.expires_at,
                },
            );
        Ok(CreatedApiKey {
            summary,
            key: issued.secret,
        })
    }

    pub async fn list(&self, owner_user_id: &UserId) -> Result<Vec<ApiKeySummary>, AuthError> {
        Ok(self
            .repository
            .list_api_keys(owner_user_id)
            .await?
            .iter()
            .map(api_key_summary)
            .collect())
    }

    pub async fn get(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
    ) -> Result<StoredApiKey, AuthError> {
        self.repository
            .load_api_key(owner_user_id, key_id)
            .await?
            .ok_or(AuthError::NotFound)
    }

    pub async fn update(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
        label: Option<String>,
        group_label: Option<String>,
        enabled: Option<bool>,
        expires_at: Option<Option<i64>>,
        quota_limit_usd: Option<Option<String>>,
        now: i64,
    ) -> Result<ApiKeySummary, AuthError> {
        let _mutation = self.mutation.lock().await;
        let current = self
            .repository
            .load_api_key(owner_user_id, key_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if expires_at
            .flatten()
            .is_some_and(|expires_at| expires_at <= now)
        {
            return Err(AuthError::InvalidExpiry);
        }
        let label = match label {
            Some(value) => normalize_label(value)?,
            None => current.label.clone(),
        };
        let group_label = match group_label {
            Some(value) => normalize_group_label(value)?,
            None => current.group_label.clone(),
        };
        let quota_limit_atoms = match quota_limit_usd {
            None => None,
            Some(None) => Some(None),
            Some(Some(value)) => Some(Some(
                parse_quota_limit_usd(&value).map_err(|_| AuthError::InvalidQuotaLimit)?,
            )),
        };
        let enabled = enabled.unwrap_or(current.enabled);
        let expires_at = expires_at.unwrap_or(current.expires_at);
        let account_ids = self
            .repository
            .list_visible_account_ids_by_group_label(owner_user_id, &group_label)
            .await?;
        if account_ids.is_empty() {
            return Err(AuthError::GroupNotFound);
        }
        let removed = self.remove_active(owner_user_id, key_id);
        let updated = match self
            .repository
            .update_api_key(
                owner_user_id,
                key_id,
                &group_label,
                &label,
                enabled,
                expires_at,
                quota_limit_atoms,
                now,
            )
            .await
        {
            Ok(Some(key)) => key,
            Ok(None) => {
                self.restore_active(removed);
                return Err(AuthError::NotFound);
            }
            Err(error) => {
                self.restore_active(removed);
                return Err(error.into());
            }
        };
        if updated.quota_limit_atoms.is_some() {
            self.remember_spent(&updated.id, &updated.spent_atoms);
        } else {
            self.forget_quota_state(&updated.id);
        }
        if updated.enabled {
            self.active
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    digest_secret(updated.key.expose_secret()),
                    ActiveApiKey {
                        id: updated.id.clone(),
                        owner_user_id: updated.owner_user_id.clone(),
                        label: updated.label.clone(),
                        group_label: updated.group_label.clone(),
                        quota_limit_atoms: updated.quota_limit_atoms.clone(),
                        expires_at: updated.expires_at,
                    },
                );
        }
        Ok(api_key_summary(&updated))
    }

    pub async fn delete(&self, owner_user_id: &UserId, key_id: &ApiKeyId) -> Result<(), AuthError> {
        let _mutation = self.mutation.lock().await;
        let removed = self.remove_active(owner_user_id, key_id);
        match self.repository.delete_api_key(owner_user_id, key_id).await {
            Ok(true) => {
                self.forget_quota_state(key_id);
                Ok(())
            }
            Ok(false) => {
                self.restore_active(removed);
                Err(AuthError::NotFound)
            }
            Err(error) => {
                self.restore_active(removed);
                Err(error.into())
            }
        }
    }

    /// Reject when the key's lifetime observed spend has already reached its USD ceiling.
    pub async fn ensure_quota_available(&self, key: &AuthenticatedApiKey) -> Result<(), AuthError> {
        let Some(limit) = key.quota_limit_atoms.as_deref() else {
            return Ok(());
        };
        let persisted = self
            .repository
            .load_api_key_spent_atoms(&key.key_id)
            .await?
            .ok_or(AuthError::QuotaLedgerUnavailable)?;
        let persisted = match quota_spend(&persisted) {
            QuotaSpend::Known(value) => value,
            QuotaSpend::Unavailable => return Err(AuthError::QuotaLedgerUnavailable),
        };
        let memory = self
            .quota_spent
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key.key_id)
            .cloned();
        let spent = match memory {
            Some(QuotaSpend::Unavailable) => return Err(AuthError::QuotaLedgerUnavailable),
            Some(QuotaSpend::Known(memory))
                if atoms_ge(&memory, &persisted)
                    .map_err(|_| AuthError::QuotaLedgerUnavailable)? =>
            {
                memory
            }
            _ => {
                self.remember_spent(&key.key_id, &persisted);
                persisted
            }
        };
        if atoms_ge(&spent, limit).map_err(|_| AuthError::QuotaLedgerUnavailable)? {
            return Err(AuthError::QuotaExceeded);
        }
        Ok(())
    }

    /// Acquire the only in-flight slot for a quota-limited key and check its
    /// current spend while that slot is held.
    pub async fn acquire_quota(
        &self,
        key: &AuthenticatedApiKey,
    ) -> Result<ApiKeyQuotaLease, AuthError> {
        if key.quota_limit_atoms.is_none() {
            return Ok(ApiKeyQuotaLease { _guard: None });
        }
        let gate = {
            let mut gates = self
                .quota_gates
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            Arc::clone(
                gates
                    .entry(key.key_id.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let guard = gate
            .try_lock_owned()
            .map_err(|_| AuthError::QuotaInFlight)?;
        if let Err(error) = self.ensure_quota_available(key).await {
            drop(guard);
            return Err(error);
        }
        Ok(ApiKeyQuotaLease {
            _guard: Some(guard),
        })
    }

    /// Record known cost immediately for admission checks. The durable writer
    /// records the same amount transactionally; keeping the high-water mark in
    /// memory closes the gap between response completion and database commit.
    pub fn record_spend(&self, api_key_id: &ApiKeyId, atoms: i128) {
        if atoms <= 0 {
            return;
        }
        let mut spent = self
            .quota_spent
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let current = match spent.get(api_key_id) {
            Some(QuotaSpend::Unavailable) => return,
            Some(QuotaSpend::Known(value)) => value.as_str(),
            None => return,
        };
        let next = add_atoms(current, &atoms.to_string())
            .map_or(QuotaSpend::Unavailable, QuotaSpend::Known);
        spent.insert(api_key_id.clone(), next);
    }

    pub async fn account_ids_for_key(
        &self,
        owner_user_id: &UserId,
        group_label: &str,
    ) -> Result<Vec<String>, AuthError> {
        Ok(self
            .repository
            .list_visible_account_ids_by_group_label(owner_user_id, group_label)
            .await?)
    }

    fn remove_active(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
    ) -> Option<([u8; 32], ActiveApiKey)> {
        let mut active = self.active.write().unwrap_or_else(PoisonError::into_inner);
        let digest = active.iter().find_map(|(digest, key)| {
            (key.id == *key_id && key.owner_user_id == *owner_user_id).then_some(*digest)
        })?;
        active.remove_entry(&digest)
    }

    fn restore_active(&self, removed: Option<([u8; 32], ActiveApiKey)>) {
        if let Some((digest, key)) = removed {
            self.active
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(digest, key);
        }
    }

    fn remember_spent(&self, api_key_id: &ApiKeyId, spent_atoms: &str) {
        let mut spent = self
            .quota_spent
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let incoming = quota_spend(spent_atoms);
        match (spent.get(api_key_id), incoming) {
            (_, QuotaSpend::Unavailable) | (Some(QuotaSpend::Unavailable), _) => {
                spent.insert(api_key_id.clone(), QuotaSpend::Unavailable);
            }
            (Some(QuotaSpend::Known(current)), QuotaSpend::Known(next)) => {
                match atoms_ge(&next, current) {
                    Ok(true) => {
                        spent.insert(api_key_id.clone(), QuotaSpend::Known(next));
                    }
                    Ok(false) => {}
                    Err(()) => {
                        spent.insert(api_key_id.clone(), QuotaSpend::Unavailable);
                    }
                }
            }
            (None, QuotaSpend::Known(next)) => {
                spent.insert(api_key_id.clone(), QuotaSpend::Known(next));
            }
        }
    }

    fn forget_quota_state(&self, api_key_id: &ApiKeyId) {
        self.quota_spent
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(api_key_id);
        self.quota_gates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(api_key_id);
    }
}

fn quota_spend(value: &str) -> QuotaSpend {
    if value.is_empty() || value.len() > 64 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        QuotaSpend::Unavailable
    } else {
        QuotaSpend::Known(value.to_owned())
    }
}

fn active_key_map(keys: Vec<StoredApiKey>) -> HashMap<[u8; 32], ActiveApiKey> {
    keys.into_iter()
        .map(|key| {
            (
                digest_secret(key.key.expose_secret()),
                ActiveApiKey {
                    id: key.id,
                    owner_user_id: key.owner_user_id,
                    label: key.label,
                    group_label: key.group_label,
                    quota_limit_atoms: key.quota_limit_atoms,
                    expires_at: key.expires_at,
                },
            )
        })
        .collect()
}

fn api_key_summary(key: &StoredApiKey) -> ApiKeySummary {
    ApiKeySummary {
        id: key.id.clone(),
        owner_user_id: key.owner_user_id.clone(),
        group_label: key.group_label.clone(),
        label: key.label.clone(),
        key: mask_api_key(key.key.expose_secret()),
        enabled: key.enabled,
        expires_at: key.expires_at,
        quota_limit_atoms: key.quota_limit_atoms.clone(),
        spent_atoms: key.spent_atoms.clone(),
        last_used_at: key.last_used_at,
        created_at: key.created_at,
        updated_at: key.updated_at,
    }
}

fn normalize_group_label(group_label: String) -> Result<String, AuthError> {
    let group_label = group_label.trim().to_owned();
    if group_label.is_empty() || group_label.chars().count() > 64 {
        return Err(AuthError::InvalidGroup);
    }
    Ok(group_label)
}

fn mask_api_key(key: &str) -> String {
    let characters = key.chars().collect::<Vec<_>>();
    if characters.len() <= 6 {
        return "*".repeat(characters.len());
    }
    let prefix = characters[..3].iter().collect::<String>();
    let suffix = characters[characters.len() - 3..]
        .iter()
        .collect::<String>();
    let masked = "*".repeat(characters.len() - 6);
    format!("{prefix}{masked}{suffix}")
}

fn normalize_username(username: String) -> Result<String, AuthError> {
    let username = username.trim().to_owned();
    if username.is_empty() || username.len() > 128 {
        return Err(AuthError::InvalidUsername);
    }
    Ok(username)
}

fn normalize_label(label: String) -> Result<String, AuthError> {
    let label = label.trim().to_owned();
    if label.is_empty() || label.len() > 128 {
        return Err(AuthError::InvalidLabel);
    }
    Ok(label)
}

fn require_super_admin(user: &UserSummary) -> Result<(), AuthError> {
    if user.role != UserRole::SuperAdmin {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

fn user_summary(user: &crate::StoredUser) -> UserSummary {
    UserSummary {
        id: user.id.clone(),
        username: user.username.clone(),
        role: user.role,
        enabled: user.enabled,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}

async fn password_hash(password: SecretString) -> Result<String, AuthError> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| AuthError::PasswordTask)?
        .map_err(AuthError::Credential)
}

async fn new_standard_user(
    username: String,
    password: SecretString,
    now: i64,
) -> Result<NewUser, AuthError> {
    Ok(NewUser {
        id: UserId::random(),
        username: normalize_username(username)?,
        password_hash: password_hash(password).await?,
        role: UserRole::User,
        enabled: true,
        created_at: now,
    })
}

fn new_user_summary(user: NewUser) -> UserSummary {
    UserSummary {
        id: user.id,
        username: user.username,
        role: user.role,
        enabled: user.enabled,
        created_at: user.created_at,
        updated_at: user.created_at,
    }
}

fn normalize_registration_code(code: &str) -> Result<&str, AuthError> {
    let code = code.trim();
    if code.len() != 43
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AuthError::InvalidRegistrationCode);
    }
    Ok(code)
}

async fn verify_password_async(password: SecretString, encoded: String) -> Result<bool, AuthError> {
    tokio::task::spawn_blocking(move || verify_password(&password, &encoded))
        .await
        .map_err(|_| AuthError::PasswordTask)?
        .map_err(AuthError::Credential)
}

async fn consume_missing_user_password(password: SecretString) {
    let _ = password;
    let _ = password_hash(SecretString::from("missing-user-placeholder".to_owned())).await;
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("initial setup is already complete")]
    AlreadyConfigured,
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    #[error("invalid API key")]
    InvalidApiKey,
    #[error("user is not allowed to perform this operation")]
    Forbidden,
    #[error("resource already exists")]
    Conflict,
    #[error("resource was not found")]
    NotFound,
    #[error("registration code is invalid or expired")]
    InvalidRegistrationCode,
    #[error("username must contain 1 to 128 characters")]
    InvalidUsername,
    #[error("label must contain 1 to 128 characters")]
    InvalidLabel,
    #[error("expiry must be in the future")]
    InvalidExpiry,
    #[error("quota limit must be a positive USD amount when set")]
    InvalidQuotaLimit,
    #[error("API key USD quota has been exhausted")]
    QuotaExceeded,
    #[error("API key already has a request in flight")]
    QuotaInFlight,
    #[error("API key quota ledger is unavailable")]
    QuotaLedgerUnavailable,
    #[error("provider group label was not found on any visible account")]
    GroupNotFound,
    #[error("provider group label is invalid")]
    InvalidGroup,
    #[error("password processing task failed")]
    PasswordTask,
    #[error(transparent)]
    Credential(#[from] CredentialError),
    #[error(transparent)]
    Repository(#[from] AuthRepositoryError),
}
