use std::{error::Error, sync::Arc};

use provider_auth::{ApiKeyAuthenticator, ApiKeyId, AuthService};
use provider_core::{AccountRepository, ProviderControl, ProxyService};
use provider_drivers::{
    anthropic_compatible::AnthropicCompatibleDriver, codex::CodexDriver, grok::GrokDriver,
    openai_compatible::OpenAiCompatibleDriver,
};
use provider_management::{ModelCatalogService, ProviderManager};
use provider_protocol::DefaultProtocolBridge;
use provider_runtime::ProviderRuntimeCatalog;
use provider_storage::{InstanceGuard, SqliteAccountRepository};
use provider_usage::{
    CatalogPrices, CatalogRefresher, DEFAULT_REFRESH_PERIOD, DEFAULT_RETENTION,
    DEFAULT_RETENTION_PERIOD, DEFAULT_WRITE_QUEUE, RetentionWorker, SpendObserver, UsageRepository,
    UsageTracking, UsageWriter, system_clock_ms,
};
use tokio::net::TcpListener;

use crate::{
    UsageServices,
    catalog_source::HttpCatalogSource,
    config::{CATALOG_SYNC_ENV, DATABASE_PATH, catalog_sync_enabled, listen_address},
    router_with_management_and_usage,
};

/// How long shutdown waits for queued usage facts before giving up on them.
const USAGE_DRAIN: std::time::Duration = std::time::Duration::from_secs(2);

pub async fn run() -> Result<(), Box<dyn Error>> {
    // Before anything touches the database. Startup recovery assumes any request
    // still marked in-flight was left by a dead run, which only holds while this
    // process is the only one using it. Held until the process exits.
    let _instance = InstanceGuard::acquire(DATABASE_PATH)?;

    let repository = Arc::new(SqliteAccountRepository::connect(DATABASE_PATH).await?);
    let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
    runtime.register_driver(Arc::new(GrokDriver::new()))?;
    runtime.register_driver(Arc::new(CodexDriver::new()))?;
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

    // Usage facts share the accounts database. Anything a previous run left in
    // flight has no knowable terminal, so it is closed as incomplete with a gap
    // before this run records anything new.
    let usage_repository = Arc::new(repository.usage_repository());
    let recovered = usage_repository
        .recover_in_flight_requests(unix_timestamp() * 1000)
        .await?;
    if recovered > 0 {
        eprintln!("closed {recovered} usage request(s) left in flight by a previous run");
    }
    let writer = Arc::new(UsageWriter::spawn(
        usage_repository.clone(),
        DEFAULT_WRITE_QUEUE,
    ));
    let spend_observer: SpendObserver = {
        let api_keys = api_keys.clone();
        Arc::new(move |api_key_id, atoms| {
            if let Ok(api_key_id) = ApiKeyId::new(api_key_id.to_owned()) {
                api_keys.record_spend(&api_key_id, atoms);
            }
        })
    };
    // Price from whatever catalog is already stored before any fetch, so a
    // restart does not lose cost estimates while it waits for the network.
    let prices = Arc::new(CatalogPrices::new());
    let refresher = Arc::new(CatalogRefresher::new(
        usage_repository.clone(),
        Arc::new(HttpCatalogSource::models_dev()?),
        prices.clone(),
        system_clock_ms,
    ));
    match refresher.install_stored().await {
        Some(revision) => println!("price catalog {} loaded from storage", &revision[..12]),
        None => println!("no stored price catalog yet; costs stay unavailable until one loads"),
    }
    if catalog_sync_enabled() {
        tokio::spawn(Arc::clone(&refresher).run(DEFAULT_REFRESH_PERIOD));
    } else {
        println!("price catalog sync disabled by {CATALOG_SYNC_ENV}");
    }

    // Raw facts expire on their own so the database does not grow without bound.
    // In-flight requests are never touched, and each cycle deletes in small
    // batches rather than one long transaction.
    let retention = Arc::new(RetentionWorker::new(
        usage_repository.clone(),
        system_clock_ms,
    ));
    println!(
        "usage retention keeps {} days of raw facts",
        DEFAULT_RETENTION.as_secs() / 86_400
    );
    tokio::spawn(retention.run(DEFAULT_RETENTION_PERIOD));

    let usage = UsageServices {
        tracking: Arc::new(UsageTracking::with_spend_observer(
            usage_repository.clone(),
            writer.clone(),
            prices.clone(),
            spend_observer,
        )),
        query: usage_repository.clone(),
        repository: usage_repository,
        catalog: prices,
        writer: writer.clone(),
    };

    let manager = ProviderManager::new(repository, runtime.clone());
    let listen_address = listen_address();
    let listener = TcpListener::bind(&listen_address).await?;

    println!("provider-core listening on http://{listen_address}");
    let result = axum::serve(
        listener,
        router_with_management_and_usage(service, manager, auth, api_keys, Some(usage)),
    )
    .await;
    runtime.shutdown();
    // Best-effort: a slow database must not hold up shutdown.
    writer.drain(USAGE_DRAIN).await;
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
