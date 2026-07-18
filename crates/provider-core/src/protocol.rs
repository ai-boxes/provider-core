use serde::{Deserialize, Serialize};

/// Downstream protocol used by the calling agent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    CodexResponses,
    ClaudeMessages,
}
