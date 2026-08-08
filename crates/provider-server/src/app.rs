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
    CatalogPrices, CatalogRefresher, DEFAULT_QUOTA_QUEUE, DEFAULT_REFRESH_PERIOD,
    DEFAULT_RETENTION, DEFAULT_RETENTION_PERIOD, DEFAULT_WRITE_QUEUE, QuotaLedgerWriter,
    RefreshOutcome, RetentionWorker, SpendObserver, UsageRepository, UsageTracking, UsageWriter,
    system_clock_ms,
};
use tokio::net::TcpListener;

use crate::{
    UsageServices,
    catalog_source::HttpCatalogSource,
    config::{
        CATALOG_SYNC_ENV, DATABASE_PATH, catalog_sync_enabled, listen_address, trusted_proxy_ip,
    },
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
    let usage_repository = Arc::new(repository.usage_repository());
    let prices = Arc::new(CatalogPrices::new());
    let refresher = Arc::new(CatalogRefresher::new(
        usage_repository.clone(),
        Arc::new(HttpCatalogSource::models_dev()?),
        prices.clone(),
        system_clock_ms,
    ));
    let stored_catalog = refresher.install_stored().await;
    match stored_catalog.as_deref() {
        Some(revision) => println!("price catalog {} loaded from storage", &revision[..12]),
        None if catalog_sync_enabled() => {
            let outcome = refresher.refresh_once().await;
            println!("initial price catalog refresh: {outcome:?}");
        }
        None => println!("no stored price catalog; model prices remain unconfigured"),
    }

    let runtime = Arc::new(ProviderRuntimeCatalog::new(repository.clone()));
    runtime.register_driver(Arc::new(GrokDriver::new()))?;
    runtime.register_driver(Arc::new(CodexDriver::new()))?;
    runtime.register_driver(Arc::new(OpenAiCompatibleDriver::new()))?;
    runtime.register_driver(Arc::new(AnthropicCompatibleDriver::new()))?;
    let model_catalog = ModelCatalogService::with_pricing(repository.clone(), prices.clone());
    for account in repository.load_enabled_accounts().await? {
        let account_id = account.id.clone();
        let kind = account.provider;
        let access = account.access();
        let account = match runtime.build_account(account) {
            Ok(account) => account,
            Err(error) => {
                eprintln!("failed to build provider account {account_id}: {error}");
                continue;
            }
        };
        let models = match model_catalog
            .refresh(account.as_ref(), unix_timestamp())
            .await
        {
            Ok(models) => models,
            Err(error) => {
                eprintln!("failed to discover models for provider account {account_id}: {error}");
                continue;
            }
        };
        if let Err(error) = runtime
            .activate_account(kind, account, models.models, access)
            .await
        {
            eprintln!("failed to activate provider account {account_id}: {error}");
        }
    }

    let service = ProxyService::with_router(runtime.clone(), Arc::new(DefaultProtocolBridge));
    let auth = AuthService::new(repository.clone());
    let api_keys = ApiKeyAuthenticator::load(repository.clone()).await?;

    // Usage facts share the accounts database. Anything a previous run left in
    // flight has no knowable terminal, so it is closed as incomplete with a gap
    // before this run records anything new.
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
    let quota_writer = Arc::new(QuotaLedgerWriter::spawn(
        usage_repository.clone(),
        DEFAULT_QUOTA_QUEUE,
    ));
    let spend_observer: SpendObserver = {
        let api_keys = api_keys.clone();
        Arc::new(move |api_key_id, atoms| {
            if let Ok(api_key_id) = ApiKeyId::new(api_key_id.to_owned()) {
                api_keys.record_quota_result(&api_key_id, atoms);
            }
        })
    };
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
            quota_writer.clone(),
            spend_observer,
        )),
        query: usage_repository,
    };

    let manager = ProviderManager::with_model_pricing_catalog(repository, runtime.clone(), prices);
    if catalog_sync_enabled() {
        let refresher = Arc::clone(&refresher);
        let manager = manager.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(DEFAULT_REFRESH_PERIOD);
            loop {
                ticker.tick().await;
                if refresher.refresh_once().await == RefreshOutcome::Installed
                    && let Err(error) = manager
                        .refresh_enabled_model_catalogs(unix_timestamp())
                        .await
                {
                    eprintln!("failed to apply refreshed prices to routed models: {error}");
                }
            }
        });
    } else {
        println!("price catalog sync disabled by {CATALOG_SYNC_ENV}");
    }
    let listen_address = listen_address();
    let listener = TcpListener::bind(&listen_address).await?;

    println!("provider-core listening on http://{listen_address}");
    let result = axum::serve(
        listener,
        router_with_management_and_usage(
            service,
            manager,
            auth,
            api_keys,
            Some(usage),
            trusted_proxy_ip()?,
        )
        .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    runtime.shutdown();
    if !quota_writer.drain().await {
        return Err("quota ledger writer stopped before shutdown drain completed".into());
    }
    // Best-effort: a slow database must not hold up shutdown.
    writer.drain(USAGE_DRAIN).await;
    result?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler must install");
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.expect("Ctrl-C handler must install");
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("Ctrl-C handler must install");
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}
