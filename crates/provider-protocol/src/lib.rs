//! Wire protocol conversion for provider-core.

#![forbid(unsafe_code)]

mod anthropic;
mod bridge;
mod claude;
mod openai_chat;
mod sse;
mod usage_observer;

pub use bridge::DefaultProtocolBridge;
pub use usage_observer::{observe_chat_completions_usage, observe_responses_usage};
