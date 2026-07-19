//! Wire protocol conversion for provider-core.

#![forbid(unsafe_code)]

mod bridge;
mod claude;
mod sse;

pub use bridge::DefaultProtocolBridge;
