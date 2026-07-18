use std::{error::Error, sync::Arc};

use provider_core::{AccountRepository, ProxyService};
use provider_grok::{GrokProvider, grok_models};
use provider_runtime::ProviderRuntime;
use provider_storage::SqliteAccountRepository;
use tokio::net::TcpListener;

use crate::{
    config::{DATABASE_PATH, LISTEN_ADDRESS},
    router,
};

pub async fn run() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(SqliteAccountRepository::connect(DATABASE_PATH).await?);
    let runtime = ProviderRuntime::new("grok", grok_models().to_vec());
    for account in repository.load_enabled_accounts().await? {
        if account.provider.trim() != "grok" {
            return Err(format!(
                "enabled provider account {} uses unsupported provider {}",
                account.id, account.provider
            )
            .into());
        }
        runtime
            .register(Arc::new(GrokProvider::from_stored(
                account,
                repository.clone(),
            )?))
            .await?;
    }

    let service = ProxyService::new(Arc::new(runtime.clone()));
    let listener = TcpListener::bind(LISTEN_ADDRESS).await?;

    println!("provider-core listening on http://{LISTEN_ADDRESS}");
    let result = axum::serve(listener, router(service)).await;
    runtime.shutdown();
    result?;
    Ok(())
}
