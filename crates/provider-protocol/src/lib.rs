//! Wire protocol conversion for provider-core.

#![forbid(unsafe_code)]

mod anthropic;
mod bridge;
mod claude;
mod openai_chat;
mod sse;

pub use bridge::DefaultProtocolBridge;
