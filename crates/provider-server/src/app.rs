use std::{error::Error, sync::Arc};

use provider_core::ProxyService;
use provider_grok::{GrokCredentials, GrokProvider};
use tokio::net::TcpListener;

use crate::{
    config::{GROK_AUTH_PATH, LISTEN_ADDRESS},
    router,
};

pub async fn run() -> Result<(), Box<dyn Error>> {
    let credentials = GrokCredentials::load(GROK_AUTH_PATH)?;
    let service = ProxyService::new(Arc::new(GrokProvider::new(credentials)));
    let listener = TcpListener::bind(LISTEN_ADDRESS).await?;

    println!("provider-core listening on http://{LISTEN_ADDRESS}");
    axum::serve(listener, router(service)).await?;
    Ok(())
}
