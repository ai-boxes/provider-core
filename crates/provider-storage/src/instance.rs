//! A single-instance guard over the database.
//!
//! Startup recovery closes out every logical request left `in_progress`, on the
//! premise that only a dead run could have left one. A second process on the same
//! database breaks that premise: it would mark the *live* instance's in-flight
//! requests as incomplete, corrupting data that is still being written.
//!
//! The guard is an OS advisory exclusive lock on a sidecar file, taken before
//! recovery and held for the process's lifetime. The OS releases it if the process
//! dies, so a crash needs no cleanup — which a PID file could not promise.

use std::{
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;

/// Held for as long as this process may use the database. Dropping it releases
/// the lock.
pub struct InstanceGuard {
    /// The lock lives on the open file description; keeping the handle is what
    /// keeps the lock.
    _file: File,
    path: PathBuf,
}

impl InstanceGuard {
    /// Take the guard for `database_path`, or fail if another process holds it.
    ///
    /// Call this before recovery, and keep the returned value alive.
    pub fn acquire(database_path: impl AsRef<Path>) -> Result<Self, InstanceGuardError> {
        let path = lock_path(database_path.as_ref());
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|source| InstanceGuardError::Unavailable {
                path: path.clone(),
                source,
            })?;
        }
        // Never truncate: another process may hold this file open right now, and
        // the file's contents are irrelevant — the lock is the whole point.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| InstanceGuardError::Unavailable {
                path: path.clone(),
                source,
            })?;

        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file, path }),
            // Refusing to start is the point: recovering another live instance's
            // requests would destroy them.
            Err(_) => Err(InstanceGuardError::AlreadyRunning { path }),
        }
    }

    /// The sidecar file this guard holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The lock file sits beside the database rather than being the database, so
/// holding it never interferes with normal SQLite access.
fn lock_path(database_path: &Path) -> PathBuf {
    let mut name = database_path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

#[derive(Debug, Error)]
pub enum InstanceGuardError {
    #[error(
        "another provider-core instance is already using this database ({}); \
         starting a second one would corrupt in-flight request tracking",
        path.display()
    )]
    AlreadyRunning { path: PathBuf },
    #[error("could not open the instance lock file ({}): {source}", path.display())]
    Unavailable { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("provider-core-guard-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temp dir");
        path.push("provider-core.db");
        path
    }

    #[test]
    fn a_second_guard_on_the_same_database_is_refused() {
        let database = temp_db("busy");
        let first = InstanceGuard::acquire(&database).expect("first guard");

        let second = InstanceGuard::acquire(&database);
        assert!(
            matches!(second, Err(InstanceGuardError::AlreadyRunning { .. })),
            "a second instance must not be able to start"
        );

        // Releasing lets a replacement take over, which is what a restart needs.
        drop(first);
        assert!(InstanceGuard::acquire(&database).is_ok());
    }
}
