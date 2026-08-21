//! Exclusive SQLite writer for the process.
//!
//! SQLite accepts one writer at a time. Keeping every mutation on a single
//! long-lived connection makes that rule explicit in-process: callers wait on
//! this mutex instead of racing `BEGIN IMMEDIATE` across the read pool and
//! turning contention into `database is locked`.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use sqlx::{ConnectOptions, SqliteConnection, sqlite::SqliteConnectOptions};
use tokio::runtime::RuntimeFlavor;
use tokio::sync::{Mutex, MutexGuard};

/// Process-wide SQLite write owner.
#[derive(Clone)]
pub(crate) struct SqliteWriter {
    connection: Arc<Mutex<SqliteConnection>>,
}

impl SqliteWriter {
    pub(crate) async fn connect(options: SqliteConnectOptions) -> Result<Self, sqlx::Error> {
        let connection = options.connect().await?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub(crate) async fn lock(&self) -> MutexGuard<'_, SqliteConnection> {
        let mut guard = self.connection.lock().await;
        reclaim(&mut guard).await;
        guard
    }

    pub(crate) async fn begin(&self) -> Result<WriteTransaction<'_>, sqlx::Error> {
        WriteTransaction::begin(self).await
    }
}

/// An open immediate transaction on the exclusive write connection.
pub(crate) struct WriteTransaction<'a> {
    connection: Arc<Mutex<SqliteConnection>>,
    guard: Option<MutexGuard<'a, SqliteConnection>>,
    finished: bool,
}

impl<'a> WriteTransaction<'a> {
    async fn begin(writer: &'a SqliteWriter) -> Result<Self, sqlx::Error> {
        let mut guard = writer.connection.lock().await;
        reclaim(&mut guard).await;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *guard).await?;
        Ok(Self {
            connection: Arc::clone(&writer.connection),
            guard: Some(guard),
            finished: false,
        })
    }

    pub(crate) async fn commit(mut self) -> Result<(), sqlx::Error> {
        let guard = self
            .guard
            .as_mut()
            .expect("write transaction already finished");
        match sqlx::query("COMMIT").execute(&mut **guard).await {
            Ok(_) => {
                self.finished = true;
                drop(self.guard.take());
                Ok(())
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut **guard).await;
                self.finished = true;
                drop(self.guard.take());
                Err(error)
            }
        }
    }

    pub(crate) async fn rollback(mut self) -> Result<(), sqlx::Error> {
        let guard = self
            .guard
            .as_mut()
            .expect("write transaction already finished");
        let result = sqlx::query("ROLLBACK")
            .execute(&mut **guard)
            .await
            .map(|_| ());
        self.finished = true;
        drop(self.guard.take());
        result
    }
}

impl Drop for WriteTransaction<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let Some(mut guard) = self.guard.take() else {
            return;
        };
        // Prefer reclaiming before releasing the mutex so readers never observe
        // an abandoned write transaction on the multi-thread runtime used in
        // production. Current-thread runtimes cannot block here safely.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == RuntimeFlavor::MultiThread {
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        reclaim(&mut guard).await;
                    });
                });
                return;
            }
            drop(guard);
            let connection = Arc::clone(&self.connection);
            handle.spawn(async move {
                let mut guard = connection.lock().await;
                reclaim(&mut guard).await;
            });
            return;
        }
        drop(guard);
    }
}

impl Deref for WriteTransaction<'_> {
    type Target = SqliteConnection;

    fn deref(&self) -> &Self::Target {
        self.guard
            .as_ref()
            .expect("write transaction already finished")
    }
}

impl DerefMut for WriteTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard
            .as_mut()
            .expect("write transaction already finished")
    }
}

async fn reclaim(connection: &mut SqliteConnection) {
    let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
}
