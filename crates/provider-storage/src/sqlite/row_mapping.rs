use super::*;

pub(super) fn stored_account(
    row: SqliteRow,
    credential_cipher: &CredentialCipher,
) -> Result<StoredProviderAccount, AccountRepositoryError> {
    let id = row_value::<String>(&row, "id")?;
    let id = AccountId::new(id).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account ID: {error}"))
    })?;
    let auth_state = row_value::<String>(&row, "auth_state")?;
    let auth_state = AccountAuthState::from_str(&auth_state).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account auth state: {error}"))
    })?;
    let provider = row_value::<String>(&row, "provider")?;
    let provider = ProviderKind::from_str(&provider).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account type: {error}"))
    })?;
    let credential_kind = required_joined_value::<String>(&row, "credential_kind", &id)?;
    let credential_kind = CredentialKind::from_str(&credential_kind).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider credential type: {error}"))
    })?;
    let revision = required_joined_value::<i64>(&row, "revision", &id)?;
    let format_version = required_joined_value::<i64>(&row, "format_version", &id)?;
    let credential_json = required_joined_value::<String>(&row, "credential_json", &id)?;
    let credential_json = credential_cipher.decrypt(&id, &credential_json)?;
    let credential_updated_at = required_joined_value::<i64>(&row, "credential_updated_at", &id)?;

    Ok(StoredProviderAccount {
        id,
        owner_user_id: row_value(&row, "owner_user_id")?,
        visibility: provider_visibility(&row)?,
        provider,
        label: row_value(&row, "label")?,
        group_label: row_value(&row, "group_label")?,
        priority: non_negative_u32(row_value(&row, "priority")?, "provider account priority")?,
        config_json: row_value(&row, "config_json")?,
        enabled: row_value::<i64>(&row, "enabled")? != 0,
        auth_state,
        safe_error_code: row_value(&row, "safe_error_code")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
        credential: StoredCredential {
            kind: credential_kind,
            revision: non_negative_u64(revision, "credential revision")?,
            format_version: positive_u32(format_version, "credential format version")?,
            credential_json,
            expires_at: row_value(&row, "expires_at")?,
            last_refreshed_at: row_value(&row, "last_refreshed_at")?,
            updated_at: credential_updated_at,
        },
    })
}

pub(super) fn account_summary(
    row: SqliteRow,
) -> Result<ProviderAccountSummary, AccountRepositoryError> {
    let id = row_value::<String>(&row, "id")?;
    let id = AccountId::new(id).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account ID: {error}"))
    })?;
    let provider = row_value::<String>(&row, "provider")?;
    let provider = ProviderKind::from_str(&provider).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account type: {error}"))
    })?;
    let credential_kind = row_value::<String>(&row, "credential_kind")?;
    let credential_kind = CredentialKind::from_str(&credential_kind).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider credential type: {error}"))
    })?;
    let auth_state = row_value::<String>(&row, "auth_state")?;
    let auth_state = AccountAuthState::from_str(&auth_state).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account auth state: {error}"))
    })?;

    Ok(ProviderAccountSummary {
        id,
        owner_user_id: row_value(&row, "owner_user_id")?,
        visibility: provider_visibility(&row)?,
        provider,
        label: row_value(&row, "label")?,
        group_label: row_value(&row, "group_label")?,
        priority: non_negative_u32(row_value(&row, "priority")?, "provider account priority")?,
        config_json: row_value(&row, "config_json")?,
        credential_kind,
        credential_revision: row_value::<i64>(&row, "revision")?
            .try_into()
            .map_err(|_| AccountRepositoryError::new("invalid provider credential revision"))?,
        enabled: row_value::<i64>(&row, "enabled")? != 0,
        auth_state,
        safe_error_code: row_value(&row, "safe_error_code")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
    })
}

pub(super) fn stored_model(row: SqliteRow) -> Result<StoredProviderModel, AccountRepositoryError> {
    let account_id = row_value::<String>(&row, "account_id")?;
    let account_id = AccountId::new(account_id).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider account ID: {error}"))
    })?;
    let pricing = decode_model_pricing(
        row_value(&row, "pricing_source")?,
        row_value(&row, "pricing_json")?,
    )?;
    Ok(StoredProviderModel {
        account_id,
        upstream_model: row_value(&row, "upstream_model")?,
        alias: row_value(&row, "alias")?,
        enabled: row_value::<i64>(&row, "enabled")? != 0,
        available: row_value::<i64>(&row, "available")? != 0,
        routable: row_value::<i64>(&row, "routable")? != 0,
        input_modalities: decode_input_modalities(row_value(&row, "input_modalities_json")?)?,
        metadata_json: row_value(&row, "metadata_json")?,
        pricing,
        last_seen_at: row_value(&row, "last_seen_at")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
    })
}

pub(super) fn encode_input_modalities(
    input_modalities: Option<&[provider_core::ProviderModelInputModality]>,
) -> Result<Option<String>, AccountRepositoryError> {
    provider_core::validate_input_modalities(input_modalities)
        .map_err(AccountRepositoryError::new)?;
    input_modalities
        .map(|modalities| {
            serde_json::to_string(modalities).map_err(|error| {
                repository_error("failed to encode provider model input modalities", error)
            })
        })
        .transpose()
}

pub(super) fn decode_input_modalities(
    json: Option<String>,
) -> Result<Option<Vec<provider_core::ProviderModelInputModality>>, AccountRepositoryError> {
    let Some(json) = json else {
        return Ok(None);
    };
    let modalities = serde_json::from_str::<Vec<provider_core::ProviderModelInputModality>>(&json)
        .map_err(|error| {
            repository_error("failed to decode provider model input modalities", error)
        })?;
    provider_core::validate_input_modalities(Some(&modalities))
        .map_err(AccountRepositoryError::new)?;
    Ok(Some(modalities))
}

pub(super) fn encode_model_pricing(
    record: Option<&ProviderModelPricingRecord>,
) -> Result<(Option<&'static str>, Option<String>), AccountRepositoryError> {
    let Some(record) = record else {
        return Ok((None, None));
    };
    let json = serde_json::to_string(&record.pricing)
        .map_err(|error| repository_error("failed to encode provider model pricing", error))?;
    Ok((Some(record.source.as_str()), Some(json)))
}

pub(super) fn decode_model_pricing(
    source: Option<String>,
    json: Option<String>,
) -> Result<Option<ProviderModelPricingRecord>, AccountRepositoryError> {
    match (source.as_deref(), json) {
        (None, None) => Ok(None),
        (Some(source), Some(json)) => {
            let source = match source {
                "catalog" => ProviderModelPricingSource::Catalog,
                "manual" => ProviderModelPricingSource::Manual,
                _ => {
                    return Err(AccountRepositoryError::new(
                        "unknown provider model pricing source",
                    ));
                }
            };
            let pricing = serde_json::from_str::<ProviderModelPricing>(&json).map_err(|error| {
                repository_error("failed to decode provider model pricing", error)
            })?;
            if component_prices_from_model_pricing(&pricing).is_none()
                || context_price_tiers_from_model_pricing(&pricing).is_none()
            {
                return Err(AccountRepositoryError::new(
                    "stored provider model pricing is invalid",
                ));
            }
            Ok(Some(ProviderModelPricingRecord { source, pricing }))
        }
        _ => Err(AccountRepositoryError::new(
            "provider model pricing source and json must be set together",
        )),
    }
}

pub(super) fn provider_visibility(
    row: &SqliteRow,
) -> Result<ProviderVisibility, AccountRepositoryError> {
    ProviderVisibility::from_str(&row_value::<String>(row, "visibility")?).map_err(|error| {
        AccountRepositoryError::new(format!("invalid provider visibility: {error}"))
    })
}

pub(super) fn stored_user(row: SqliteRow) -> Result<StoredUser, AuthRepositoryError> {
    Ok(StoredUser {
        id: auth_user_id(&row, "id")?,
        username: auth_row_value(&row, "username")?,
        password_hash: auth_row_value(&row, "password_hash")?,
        role: auth_user_role(&row, "role")?,
        enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

pub(super) fn user_summary(row: SqliteRow) -> Result<UserSummary, AuthRepositoryError> {
    Ok(UserSummary {
        id: auth_user_id(&row, "id")?,
        username: auth_row_value(&row, "username")?,
        role: auth_user_role(&row, "role")?,
        enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

pub(super) fn stored_session(row: SqliteRow) -> Result<StoredSession, AuthRepositoryError> {
    Ok(StoredSession {
        id: auth_session_id(&row, "id")?,
        user: UserSummary {
            id: auth_user_id(&row, "user_id")?,
            username: auth_row_value(&row, "username")?,
            role: auth_user_role(&row, "role")?,
            enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
            created_at: auth_row_value(&row, "user_created_at")?,
            updated_at: auth_row_value(&row, "user_updated_at")?,
        },
        token_hash: auth_hash(&row, "token_hash")?,
        expires_at: auth_row_value(&row, "expires_at")?,
        revoked_at: auth_row_value(&row, "revoked_at")?,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

pub(super) fn stored_api_key(row: SqliteRow) -> Result<StoredApiKey, AuthRepositoryError> {
    let group_label = auth_row_value::<String>(&row, "group_label")?;
    let quota_limit_atoms = auth_row_value::<Option<String>>(&row, "quota_limit_atoms")?;
    let spent_atoms = auth_row_value::<String>(&row, "spent_atoms")?;
    if quota_limit_atoms
        .as_deref()
        .is_some_and(|value| provider_auth::format_usd_atoms(value).is_err())
        || provider_auth::format_usd_atoms(&spent_atoms).is_err()
    {
        return Err(AuthRepositoryError::new(
            "invalid API key quota ledger value",
        ));
    }
    Ok(StoredApiKey {
        id: auth_api_key_id(&row, "id")?,
        owner_user_id: auth_user_id(&row, "owner_user_id")?,
        group_label,
        label: auth_row_value(&row, "label")?,
        key: SecretString::from(auth_row_value::<String>(&row, "key")?),
        enabled: auth_row_value::<i64>(&row, "enabled")? != 0,
        expires_at: auth_row_value(&row, "expires_at")?,
        quota_limit_atoms,
        spent_atoms,
        last_used_at: auth_row_value(&row, "last_used_at")?,
        created_at: auth_row_value(&row, "created_at")?,
        updated_at: auth_row_value(&row, "updated_at")?,
    })
}

pub(super) fn auth_user_id(row: &SqliteRow, column: &str) -> Result<UserId, AuthRepositoryError> {
    UserId::new(auth_row_value::<String>(row, column)?)
        .map_err(|error| AuthRepositoryError::new(format!("invalid user ID: {error}")))
}

pub(super) fn auth_session_id(
    row: &SqliteRow,
    column: &str,
) -> Result<SessionId, AuthRepositoryError> {
    SessionId::new(auth_row_value::<String>(row, column)?)
        .map_err(|error| AuthRepositoryError::new(format!("invalid session ID: {error}")))
}

pub(super) fn auth_api_key_id(
    row: &SqliteRow,
    column: &str,
) -> Result<ApiKeyId, AuthRepositoryError> {
    ApiKeyId::new(auth_row_value::<String>(row, column)?)
        .map_err(|error| AuthRepositoryError::new(format!("invalid API key ID: {error}")))
}

pub(super) fn auth_user_role(
    row: &SqliteRow,
    column: &str,
) -> Result<UserRole, AuthRepositoryError> {
    UserRole::from_str(&auth_row_value::<String>(row, column)?)
        .map_err(|error| AuthRepositoryError::new(format!("invalid user role: {error}")))
}

pub(super) fn auth_hash(row: &SqliteRow, column: &str) -> Result<[u8; 32], AuthRepositoryError> {
    auth_row_value::<Vec<u8>>(row, column)?
        .try_into()
        .map_err(|_| AuthRepositoryError::new(format!("{column} must contain exactly 32 bytes")))
}

pub(super) fn auth_row_value<T>(row: &SqliteRow, column: &str) -> Result<T, AuthRepositoryError>
where
    for<'row> T: sqlx::Decode<'row, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(column)
        .map_err(|error| auth_repository_error("failed to decode authentication row", error))
}

pub(super) fn row_value<T>(row: &SqliteRow, column: &str) -> Result<T, AccountRepositoryError>
where
    for<'row> T: sqlx::Decode<'row, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(column)
        .map_err(|error| repository_error("failed to decode provider account row", error))
}

pub(super) fn required_joined_value<T>(
    row: &SqliteRow,
    column: &str,
    account_id: &AccountId,
) -> Result<T, AccountRepositoryError>
where
    for<'row> T: sqlx::Decode<'row, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row_value::<Option<T>>(row, column)?.ok_or_else(|| {
        AccountRepositoryError::new(format!(
            "enabled provider account {account_id} is missing credentials"
        ))
    })
}

pub(super) fn non_negative_u64(value: i64, field: &str) -> Result<u64, AccountRepositoryError> {
    u64::try_from(value)
        .map_err(|_| AccountRepositoryError::new(format!("{field} must not be negative")))
}

pub(super) fn non_negative_u32(value: i64, field: &str) -> Result<u32, AccountRepositoryError> {
    value
        .try_into()
        .map_err(|_| AccountRepositoryError::new(format!("invalid {field}")))
}

pub(super) fn positive_u32(value: i64, field: &str) -> Result<u32, AccountRepositoryError> {
    let value = u32::try_from(value)
        .map_err(|_| AccountRepositoryError::new(format!("{field} is out of range")))?;
    if value == 0 {
        return Err(AccountRepositoryError::new(format!(
            "{field} must be positive"
        )));
    }
    Ok(value)
}

pub(super) fn database_integer(value: u64, field: &str) -> Result<i64, AccountRepositoryError> {
    i64::try_from(value)
        .map_err(|_| AccountRepositoryError::new(format!("{field} is out of range")))
}

pub(super) const fn database_bool(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

pub(super) fn repository_error(
    operation: &str,
    error: impl std::fmt::Display,
) -> AccountRepositoryError {
    AccountRepositoryError::new(format!("{operation}: {error}"))
}

pub(super) fn auth_repository_error(
    operation: &str,
    error: impl std::fmt::Display,
) -> AuthRepositoryError {
    AuthRepositoryError::new(format!("{operation}: {error}"))
}
