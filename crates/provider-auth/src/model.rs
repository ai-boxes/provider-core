use std::{fmt, str::FromStr};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

macro_rules! string_id {
    ($name:ident, $error:ident, $message:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, $error> {
                let value = value.into().trim().to_owned();
                if value.is_empty() {
                    return Err($error);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn random() -> Self {
                Self(uuid::Uuid::new_v4().to_string())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = $error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        #[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
        #[error($message)]
        pub struct $error;
    };
}

string_id!(UserId, UserIdError, "user ID must not be empty");
string_id!(SessionId, SessionIdError, "session ID must not be empty");
string_id!(ApiKeyId, ApiKeyIdError, "API key ID must not be empty");

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    SuperAdmin,
    User,
}

impl UserRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SuperAdmin => "super_admin",
            Self::User => "user",
        }
    }
}

impl FromStr for UserRole {
    type Err = UserRoleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "super_admin" => Ok(Self::SuperAdmin),
            "user" => Ok(Self::User),
            _ => Err(UserRoleError),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("unsupported user role")]
pub struct UserRoleError;

#[derive(Clone, Debug)]
pub struct NewUser {
    pub id: UserId,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct NewRegistrationCode {
    pub code_hash: [u8; 32],
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredUser {
    pub id: UserId,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSummary {
    pub id: UserId,
    pub username: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct NewSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: [u8; 32],
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredSession {
    pub id: SessionId,
    pub user: UserSummary,
    pub token_hash: [u8; 32],
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct NewApiKey {
    pub id: ApiKeyId,
    pub owner_user_id: UserId,
    pub group_label: String,
    pub label: String,
    pub key: SecretString,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    /// Lifetime USD ceiling as integer atoms (10^-14 USD). `None` is unlimited.
    pub quota_limit_atoms: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredApiKey {
    pub id: ApiKeyId,
    pub owner_user_id: UserId,
    pub group_label: String,
    pub label: String,
    pub key: SecretString,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub quota_limit_atoms: Option<String>,
    /// Cumulative settled catalog cost atoms for this key.
    pub spent_atoms: String,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct ApiKeyPatch {
    pub label: Option<String>,
    pub group_label: Option<String>,
    pub enabled: Option<bool>,
    pub expires_at: Option<Option<i64>>,
    pub quota_limit_usd: Option<Option<String>>,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredApiKeyUpdate {
    pub group_label: String,
    pub label: String,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub quota_limit_atoms: Option<Option<String>>,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeySummary {
    pub id: ApiKeyId,
    pub owner_user_id: UserId,
    pub group_label: String,
    pub label: String,
    pub key: String,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub quota_limit_atoms: Option<String>,
    pub spent_atoms: String,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct CreatedApiKey {
    pub summary: ApiKeySummary,
    pub key: SecretString,
}

/// Fractional digits of a USD atom, matching observed-usage pricing.
pub const USD_ATOM_SCALE: u32 = 14;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("invalid USD atom value")]
pub struct UsdAtomsError;

/// Parse a user-facing USD amount into atom digits.
///
/// Accepts a non-negative decimal with at most [`USD_ATOM_SCALE`] fractional
/// digits. Zero and empty are rejected so a quota is either unset or positive.
pub fn parse_quota_limit_usd(input: &str) -> Result<String, UsdAtomsError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(UsdAtomsError);
    }
    let (whole, fraction) = match input.split_once('.') {
        Some((_, "")) => return Err(UsdAtomsError),
        Some((whole, fraction)) => (whole, fraction),
        None => (input, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > USD_ATOM_SCALE as usize
    {
        return Err(UsdAtomsError);
    }
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let mut fraction = fraction.to_owned();
    while fraction.len() < USD_ATOM_SCALE as usize {
        fraction.push('0');
    }
    let atoms = format!("{whole}{fraction}");
    let atoms = atoms.trim_start_matches('0');
    if atoms.is_empty() {
        return Err(UsdAtomsError);
    }
    if atoms.len() > 64 {
        return Err(UsdAtomsError);
    }
    Ok(atoms.to_owned())
}

/// Format atom digits as a full-precision USD decimal string.
pub fn format_usd_atoms(atoms: &str) -> Result<String, UsdAtomsError> {
    validate_atoms(atoms)?;
    let width = USD_ATOM_SCALE as usize;
    if atoms.len() <= width {
        Ok(format!("0.{:0>width$}", atoms, width = width))
    } else {
        let split = atoms.len() - width;
        Ok(format!("{}.{}", &atoms[..split], &atoms[split..]))
    }
}

/// Compare two non-negative atom digit strings without parsing to a fixed int.
pub fn atoms_ge(left: &str, right: &str) -> Result<bool, UsdAtomsError> {
    validate_atoms(left)?;
    validate_atoms(right)?;

    fn normalize(value: &str) -> &str {
        let trimmed = value.trim_start_matches('0');
        if trimmed.is_empty() { "0" } else { trimmed }
    }
    let left = normalize(left);
    let right = normalize(right);
    Ok(match left.len().cmp(&right.len()) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => left >= right,
    })
}

/// Add two non-negative atom digit strings.
pub fn add_atoms(left: &str, right: &str) -> Result<String, UsdAtomsError> {
    validate_atoms(left)?;
    validate_atoms(right)?;
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut carry = 0u8;
    let mut out = Vec::with_capacity(left.len().max(right.len()) + 1);
    let mut i = left.len();
    let mut j = right.len();
    while i > 0 || j > 0 || carry > 0 {
        let mut sum = carry;
        if i > 0 {
            i -= 1;
            sum += left[i] - b'0';
        }
        if j > 0 {
            j -= 1;
            sum += right[j] - b'0';
        }
        out.push(b'0' + (sum % 10));
        carry = sum / 10;
    }
    out.reverse();
    let text = String::from_utf8(out).map_err(|_| UsdAtomsError)?;
    if text.len() > 64 {
        return Err(UsdAtomsError);
    }
    Ok(text)
}

fn validate_atoms(value: &str) -> Result<(), UsdAtomsError> {
    if value.is_empty() || value.len() > 64 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UsdAtomsError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{add_atoms, atoms_ge, format_usd_atoms, parse_quota_limit_usd};

    #[test]
    fn quota_parser_accepts_positive_usd_and_rejects_invalid_limits() {
        assert_eq!(
            parse_quota_limit_usd("12.5"),
            Ok("1250000000000000".to_owned())
        );
        assert_eq!(
            parse_quota_limit_usd("0.00000000000001"),
            Ok("1".to_owned())
        );
        assert!(parse_quota_limit_usd("").is_err());
        assert!(parse_quota_limit_usd("0").is_err());
        assert!(parse_quota_limit_usd("-1").is_err());
        assert!(parse_quota_limit_usd("1.").is_err());
        assert!(parse_quota_limit_usd("1.000000000000001").is_err());
    }

    #[test]
    fn atom_operations_reject_empty_values() {
        assert!(format_usd_atoms("").is_err());
        assert!(atoms_ge("", "0").is_err());
        assert!(atoms_ge("0", "").is_err());
        assert!(add_atoms("", "0").is_err());
        assert!(add_atoms("0", "").is_err());
    }
}
