//! HTTP server composition for provider-core.

#![forbid(unsafe_code)]

mod app;
mod config;
mod http;

pub use app::run;
pub use http::router;
