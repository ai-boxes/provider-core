use std::{error::Error, sync::Arc};

use provider_auth::{ApiKeyAuthenticator, AuthService};
use provider_core::{AccountRepository, ProviderControl, ProxyService};
use provider_drivers::{
    anthropic_compatible::AnthropicCompatibleDriver, grok::GrokDriver,
    openai_compatible::OpenAiCompatibleDriver,
};
use provider_management::{ModelCatalogService, ProviderManager};
use provider_protocol::DefaultProtocolBridge;
use provider_runtime::ProviderRuntimeCatalog;
use provider_storage::SqliteAccountRepository;
use tokio::net::TcpListener;

use crate::{
    config::{DATABASE_PATH, LISTEN_ADDRESS},
    router_with_management,
};

pub async fn run() -> Result<(), Box<dyn Error>> {
    let repository = Arc::new(SqliteAccountRepository::connect(DATABASE_PATH).await?);
    let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
    runtime.register_driver(Arc::new(GrokDriver::new()))?;
    runtime.register_driver(Arc::new(OpenAiCompatibleDriver::new()))?;
    runtime.register_driver(Arc::new(AnthropicCompatibleDriver::new()))?;
    let model_catalog = ModelCatalogService::new(repository.clone());
    for account in repository.load_enabled_accounts().await? {
        let kind = account.provider;
        let access = account.access();
        let account = runtime.build_account(account)?;
        let models = model_catalog
            .refresh(account.as_ref(), unix_timestamp())
            .await?;
        if let Some(warning) = models.warning.as_deref() {
            eprintln!(
                "provider model discovery used {:?} catalog for account {}: {warning}",
                models.source,
                account.account_id()
            );
        }
        runtime
            .activate_account(kind, account, models.models, access)
            .await?;
    }

    let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
    let auth = AuthService::new(repository.clone());
    let api_keys = ApiKeyAuthenticator::load(repository.clone()).await?;
    let manager = ProviderManager::new(repository, runtime.clone());
    let listener = TcpListener::bind(LISTEN_ADDRESS).await?;

    println!("provider-core listening on http://{LISTEN_ADDRESS}");
    let result = axum::serve(
        listener,
        router_with_management(service, manager, auth, api_keys),
    )
    .await;
    runtime.shutdown();
    result?;
    Ok(())
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}
