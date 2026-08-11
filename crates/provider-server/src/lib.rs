//! HTTP server composition for provider-core.

#![forbid(unsafe_code)]

mod app;
mod auth_http;
mod catalog_source;
mod config;
mod http;
mod management_http;
mod usage_http;

pub use app::run;
pub use catalog_source::HttpCatalogSource;
pub use http::{
    router, router_with_management, router_with_management_and_usage, router_with_usage,
};
pub use usage_http::UsageServices;
