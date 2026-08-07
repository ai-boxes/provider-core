use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PASSWORD_MIN_CHARACTERS: usize = 6;
pub const PASSWORD_MAX_BYTES: usize = 1024;
pub const API_KEY_MIN_CHARACTERS: usize = 16;
pub const API_KEY_MAX_BYTES: usize = 256;
pub const ACCESS_TOKEN_TTL_SECONDS: i64 = 4 * 60 * 60;
pub const REFRESH_TOKEN_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const ABSOLUTE_SESSION_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

const TOKEN_RANDOM_BYTES: usize = 32;
const PASSWORD_SALT_BYTES: usize = 16;

pub struct IssuedSecret {
    pub secret: SecretString,
    pub digest: [u8; 32],
}

pub struct AccessRefreshTokens {
    pub access: IssuedSecret,
    pub refresh: IssuedSecret,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub absolute_expires_at: i64,
}

pub fn validate_password(password: &SecretString) -> Result<(), CredentialError> {
    let password = password.expose_secret();
    if password.chars().count() < PASSWORD_MIN_CHARACTERS {
        return Err(CredentialError::PasswordTooShort);
    }
    if password.len() > PASSWORD_MAX_BYTES {
        return Err(CredentialError::PasswordTooLong);
    }
    Ok(())
}

pub fn hash_password(password: &SecretString) -> Result<String, CredentialError> {
    validate_password(password)?;
    let mut salt = [0_u8; PASSWORD_SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|_| CredentialError::RandomSource)?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| CredentialError::PasswordHash)?;
    Argon2::default()
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| CredentialError::PasswordHash)
}

pub fn verify_password(password: &SecretString, encoded: &str) -> Result<bool, CredentialError> {
    let hash = PasswordHash::new(encoded).map_err(|_| CredentialError::PasswordHash)?;
    Ok(Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &hash)
        .is_ok())
}

pub fn issue_session_tokens(now: i64) -> Result<AccessRefreshTokens, CredentialError> {
    let absolute_expires_at = checked_add(now, ABSOLUTE_SESSION_TTL_SECONDS)?;
    session_tokens(now, absolute_expires_at)
}

pub fn rotate_session_tokens(
    now: i64,
    absolute_expires_at: i64,
) -> Result<AccessRefreshTokens, CredentialError> {
    if now >= absolute_expires_at {
        return Err(CredentialError::SessionExpired);
    }
    session_tokens(now, absolute_expires_at)
}

pub fn issue_api_key(custom: Option<SecretString>) -> Result<IssuedSecret, CredentialError> {
    match custom {
        Some(secret) => {
            let value = secret.expose_secret();
            if value.chars().count() < API_KEY_MIN_CHARACTERS {
                return Err(CredentialError::ApiKeyTooShort);
            }
            if value.len() > API_KEY_MAX_BYTES {
                return Err(CredentialError::ApiKeyTooLong);
            }
            Ok(IssuedSecret {
                digest: digest_secret(value),
                secret,
            })
        }
        None => random_secret(),
    }
}

pub fn issue_registration_code() -> Result<IssuedSecret, CredentialError> {
    random_secret()
}

#[must_use]
pub fn digest_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn session_tokens(
    now: i64,
    absolute_expires_at: i64,
) -> Result<AccessRefreshTokens, CredentialError> {
    let access_expires_at = checked_add(now, ACCESS_TOKEN_TTL_SECONDS)?.min(absolute_expires_at);
    let refresh_expires_at = checked_add(now, REFRESH_TOKEN_TTL_SECONDS)?.min(absolute_expires_at);
    if access_expires_at <= now || refresh_expires_at <= now {
        return Err(CredentialError::SessionExpired);
    }
    Ok(AccessRefreshTokens {
        access: random_secret()?,
        refresh: random_secret()?,
        access_expires_at,
        refresh_expires_at,
        absolute_expires_at,
    })
}

fn random_secret() -> Result<IssuedSecret, CredentialError> {
    let mut random = [0_u8; TOKEN_RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(|_| CredentialError::RandomSource)?;
    let value = URL_SAFE_NO_PAD.encode(random);
    Ok(IssuedSecret {
        digest: digest_secret(&value),
        secret: SecretString::from(value),
    })
}

fn checked_add(value: i64, seconds: i64) -> Result<i64, CredentialError> {
    value
        .checked_add(seconds)
        .ok_or(CredentialError::TimestampOutOfRange)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialError {
    #[error("password must contain at least 6 characters")]
    PasswordTooShort,
    #[error("password must not exceed 1024 bytes")]
    PasswordTooLong,
    #[error("API key must contain at least 16 characters")]
    ApiKeyTooShort,
    #[error("API key must not exceed 256 bytes")]
    ApiKeyTooLong,
    #[error("secure random source is unavailable")]
    RandomSource,
    #[error("failed to process password hash")]
    PasswordHash,
    #[error("session has reached its maximum lifetime")]
    SessionExpired,
    #[error("credential timestamp is out of range")]
    TimestampOutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_password_and_enforces_real_password_boundary() {
        let password = SecretString::from("secret".to_owned());
        let hash = hash_password(&password).expect("password hash");

        assert!(verify_password(&password, &hash).expect("verify password"));
        assert!(
            !verify_password(&SecretString::from("wrong1".to_owned()), &hash)
                .expect("reject wrong password")
        );
        assert_eq!(
            validate_password(&SecretString::from("short".to_owned())),
            Err(CredentialError::PasswordTooShort)
        );
        assert!(!hash.contains("secret"));
    }

    #[test]
    fn rotates_tokens_without_exceeding_absolute_session_expiry() {
        let initial = issue_session_tokens(100).expect("initial tokens");
        let near_end = initial.absolute_expires_at - 60;
        let rotated =
            rotate_session_tokens(near_end, initial.absolute_expires_at).expect("rotated tokens");

        assert_eq!(rotated.access_expires_at, initial.absolute_expires_at);
        assert_eq!(rotated.refresh_expires_at, initial.absolute_expires_at);
        assert_ne!(initial.access.digest, rotated.access.digest);
        assert_ne!(initial.refresh.digest, rotated.refresh.digest);
    }

    #[test]
    fn accepts_custom_api_key_and_generates_random_key() {
        let custom_value = "custom-key-12345";
        let custom =
            issue_api_key(Some(SecretString::from(custom_value.to_owned()))).expect("custom key");
        let generated = issue_api_key(None).expect("generated key");

        assert_eq!(custom.digest, digest_secret(custom_value));
        assert_eq!(generated.secret.expose_secret().len(), 43);
        assert_ne!(custom.digest, generated.digest);
    }

    #[test]
    fn registration_code_is_url_safe_and_hashed() {
        let issued = issue_registration_code().expect("registration code");
        let code = issued.secret.expose_secret();

        assert_eq!(code.len(), 43);
        assert!(
            code.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_eq!(issued.digest, digest_secret(code));
    }
}
