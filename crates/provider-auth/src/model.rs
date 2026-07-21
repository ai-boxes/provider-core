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
    pub access_token_hash: [u8; 32],
    pub refresh_token_hash: [u8; 32],
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub absolute_expires_at: i64,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredSession {
    pub id: SessionId,
    pub user: UserSummary,
    pub access_token_hash: [u8; 32],
    pub refresh_token_hash: [u8; 32],
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub absolute_expires_at: i64,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct NewApiKey {
    pub id: ApiKeyId,
    pub owner_user_id: UserId,
    pub label: String,
    pub key: SecretString,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredApiKey {
    pub id: ApiKeyId,
    pub owner_user_id: UserId,
    pub label: String,
    pub key: SecretString,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeySummary {
    pub id: ApiKeyId,
    pub owner_user_id: UserId,
    pub label: String,
    pub key: String,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct CreatedApiKey {
    pub summary: ApiKeySummary,
    pub key: SecretString,
}
