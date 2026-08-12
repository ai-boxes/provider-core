//! SQLite persistence for observed usage facts.
//!
//! Enum values are mapped to column text by explicit `match`, not by reusing a
//! serde rename. The vocabulary in the database is a schema decision guarded by
//! `CHECK` constraints, so adding a variant should fail to compile here and force
//! that decision, rather than silently write a value the schema rejects.
//!
//! Token counts follow one rule end to end: the column holds a known number, and
//! `NULL` means "not a known number". The reason it is not known lives in
//! `token_kinds_json`, which carries an entry for every metric that is *not* a
//! plain provider-reported value — so a fully reported attempt stores `{}`.

mod codec;
mod repository;

use sqlx::SqlitePool;

pub(crate) use codec::{attempt_facts, usage_error};

/// Observed-usage facts stored in the same SQLite database as accounts and auth.
///
/// One database keeps the deployment a single file to back up and a single set of
/// migrations. Usage writes happen after a response reaches its terminal state,
/// so they do not sit on the proxy's hot path and do not need a connection of
/// their own.
#[derive(Clone)]
pub struct SqliteUsageRepository {
    pub(crate) pool: SqlitePool,
}

impl SqliteUsageRepository {
    #[must_use]
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(test)]
mod tests;
