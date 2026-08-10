use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PASSWORD_MIN_CHARACTERS: usize = 6;
pub const PASSWORD_MAX_BYTES: usize = 1024;
pub const SESSION_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

const TOKEN_RANDOM_BYTES: usize = 32;
const PASSWORD_SALT_BYTES: usize = 16;

pub struct IssuedSecret {
    pub secret: SecretString,
    pub digest: [u8; 32],
}

pub struct IssuedSession {
    pub token: IssuedSecret,
    pub expires_at: i64,
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

pub fn issue_session(now: i64) -> Result<IssuedSession, CredentialError> {
    Ok(IssuedSession {
        token: random_secret()?,
        expires_at: checked_add(now, SESSION_TTL_SECONDS)?,
    })
}

pub fn issue_api_key() -> Result<IssuedSecret, CredentialError> {
    random_secret()
}

pub fn issue_registration_code() -> Result<IssuedSecret, CredentialError> {
    random_secret()
}

#[must_use]
pub fn digest_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
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
    #[error("secure random source is unavailable")]
    RandomSource,
    #[error("failed to process password hash")]
    PasswordHash,
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
    fn issues_one_fixed_lifetime_session_token() {
        let session = issue_session(100).expect("session token");

        assert_eq!(session.expires_at, 100 + SESSION_TTL_SECONDS);
        assert_eq!(
            session.token.digest,
            digest_secret(session.token.secret.expose_secret())
        );
    }

    #[test]
    fn generates_random_api_key() {
        let generated = issue_api_key().expect("generated key");

        assert_eq!(generated.secret.expose_secret().len(), 43);
        assert_eq!(
            generated.digest,
            digest_secret(generated.secret.expose_secret())
        );
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
