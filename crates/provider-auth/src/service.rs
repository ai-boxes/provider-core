use std::{
    collections::HashMap,
    sync::{Arc, PoisonError, RwLock},
};

use secrecy::SecretString;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    ApiKeyId, ApiKeySummary, AuthRepository, AuthRepositoryError, CreatedApiKey, CredentialError,
    InitialUserCreateOutcome, NewApiKey, NewSession, NewUser, RefreshSessionOutcome, SessionId,
    StoredApiKey, UserId, UserRole, UserSummary, digest_secret, hash_password, issue_api_key,
    issue_session_tokens, rotate_session_tokens, verify_password,
};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSession {
    pub session_id: SessionId,
    pub user: UserSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedApiKey {
    pub key_id: ApiKeyId,
    pub owner_user_id: UserId,
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
        let tokens = issue_session_tokens(now)?;
        if self
            .repository
            .create_initial_user(
                user,
                NewSession {
                    id: SessionId::random(),
                    user_id: user_id.clone(),
                    access_token_hash: tokens.access.digest,
                    refresh_token_hash: tokens.refresh.digest,
                    access_expires_at: tokens.access_expires_at,
                    refresh_expires_at: tokens.refresh_expires_at,
                    absolute_expires_at: tokens.absolute_expires_at,
                    created_at: now,
                },
            )
            .await?
            != InitialUserCreateOutcome::Created
        {
            return Err(AuthError::AlreadyConfigured);
        }
        Ok(SessionGrant {
            user: UserSummary {
                id: user_id,
                username,
                role: UserRole::SuperAdmin,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            access_token: tokens.access.secret,
            refresh_token: tokens.refresh.secret,
            access_expires_at: tokens.access_expires_at,
            refresh_expires_at: tokens.refresh_expires_at,
        })
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
        let username = normalize_username(username)?;
        let password_hash = password_hash(password).await?;
        let user = NewUser {
            id: UserId::random(),
            username: username.clone(),
            password_hash,
            role: UserRole::User,
            enabled: true,
            created_at: now,
        };
        if !self.repository.create_user(user.clone()).await? {
            return Err(AuthError::Conflict);
        }
        Ok(UserSummary {
            id: user.id,
            username,
            role: UserRole::User,
            enabled: true,
            created_at: now,
            updated_at: now,
        })
    }

    async fn create_session(&self, user: UserSummary, now: i64) -> Result<SessionGrant, AuthError> {
        let tokens = issue_session_tokens(now)?;
        self.repository
            .create_session(NewSession {
                id: SessionId::random(),
                user_id: user.id.clone(),
                access_token_hash: tokens.access.digest,
                refresh_token_hash: tokens.refresh.digest,
                access_expires_at: tokens.access_expires_at,
                refresh_expires_at: tokens.refresh_expires_at,
                absolute_expires_at: tokens.absolute_expires_at,
                created_at: now,
            })
            .await?;
        Ok(SessionGrant {
            user,
            access_token: tokens.access.secret,
            refresh_token: tokens.refresh.secret,
            access_expires_at: tokens.access_expires_at,
            refresh_expires_at: tokens.refresh_expires_at,
        })
    }
}

#[derive(Clone)]
pub struct ApiKeyAuthenticator {
    repository: Arc<dyn AuthRepository>,
    active: Arc<RwLock<HashMap<[u8; 32], ActiveApiKey>>>,
    mutation: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct ActiveApiKey {
    id: ApiKeyId,
    owner_user_id: UserId,
    expires_at: Option<i64>,
}

impl ApiKeyAuthenticator {
    pub async fn load(repository: Arc<dyn AuthRepository>) -> Result<Self, AuthError> {
        let keys = repository.load_active_api_keys().await?;
        Ok(Self {
            repository,
            active: Arc::new(RwLock::new(active_key_map(keys))),
            mutation: Arc::new(Mutex::new(())),
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
        })
    }

    pub async fn create(
        &self,
        owner_user_id: &UserId,
        label: String,
        custom: Option<SecretString>,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<CreatedApiKey, AuthError> {
        let label = normalize_label(label)?;
        if expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(AuthError::InvalidExpiry);
        }
        let issued = issue_api_key(custom)?;
        let key = NewApiKey {
            id: ApiKeyId::random(),
            owner_user_id: owner_user_id.clone(),
            label,
            key_hash: issued.digest,
            enabled: true,
            expires_at,
            created_at: now,
        };
        let _mutation = self.mutation.lock().await;
        if !self.repository.create_api_key(key.clone()).await? {
            return Err(AuthError::Conflict);
        }
        self.active
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                key.key_hash,
                ActiveApiKey {
                    id: key.id.clone(),
                    owner_user_id: key.owner_user_id.clone(),
                    expires_at: key.expires_at,
                },
            );
        Ok(CreatedApiKey {
            summary: ApiKeySummary {
                id: key.id,
                owner_user_id: key.owner_user_id,
                label: key.label,
                enabled: true,
                expires_at,
                last_used_at: None,
                created_at: now,
                updated_at: now,
            },
            key: issued.secret,
        })
    }

    pub async fn list(&self, owner_user_id: &UserId) -> Result<Vec<ApiKeySummary>, AuthError> {
        Ok(self.repository.list_api_keys(owner_user_id).await?)
    }

    pub async fn set_enabled(
        &self,
        owner_user_id: &UserId,
        key_id: &ApiKeyId,
        enabled: bool,
        now: i64,
    ) -> Result<(), AuthError> {
        let _mutation = self.mutation.lock().await;
        let removed = if enabled {
            None
        } else {
            self.remove_active(owner_user_id, key_id)
        };
        let updated = match self
            .repository
            .set_api_key_enabled(owner_user_id, key_id, enabled, now)
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
        if enabled {
            self.active
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    updated.key_hash,
                    ActiveApiKey {
                        id: updated.id,
                        owner_user_id: updated.owner_user_id,
                        expires_at: updated.expires_at,
                    },
                );
        }
        Ok(())
    }

    pub async fn delete(&self, owner_user_id: &UserId, key_id: &ApiKeyId) -> Result<(), AuthError> {
        let _mutation = self.mutation.lock().await;
        let removed = self.remove_active(owner_user_id, key_id);
        match self.repository.delete_api_key(owner_user_id, key_id).await {
            Ok(true) => Ok(()),
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
}

fn active_key_map(keys: Vec<StoredApiKey>) -> HashMap<[u8; 32], ActiveApiKey> {
    keys.into_iter()
        .map(|key| {
            (
                key.key_hash,
                ActiveApiKey {
                    id: key.id,
                    owner_user_id: key.owner_user_id,
                    expires_at: key.expires_at,
                },
            )
        })
        .collect()
}

fn normalize_username(username: String) -> Result<String, AuthError> {
    let username = username.trim().to_lowercase();
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
    #[error("username must contain 1 to 128 characters")]
    InvalidUsername,
    #[error("label must contain 1 to 128 characters")]
    InvalidLabel,
    #[error("expiry must be in the future")]
    InvalidExpiry,
    #[error("password processing task failed")]
    PasswordTask,
    #[error(transparent)]
    Credential(#[from] CredentialError),
    #[error(transparent)]
    Repository(#[from] AuthRepositoryError),
}
