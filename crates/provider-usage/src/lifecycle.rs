//! The terminal-status merge: how an execution outcome and a downstream
//! delivery outcome combine into one logical terminal.
//!
//! This is the pure decision table the reducer applies. Keeping it a total
//! function of two typed inputs means duplicate, out-of-order, or late events
//! can only ever resolve to the same terminal, never flip it.

use serde::{Deserialize, Serialize};

use crate::attempt::LogicalStatus;

/// The upstream execution side's terminal for a logical request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// A stable, successful upstream terminal was observed.
    StableSuccessTerminal,
    /// A stable failure with no downstream bytes sent (route/prepare/dispatch).
    StableFailure,
    /// The translator or upstream stream errored after starting to produce output.
    TranslatorOrStreamError,
    /// The upstream stream reached EOF without a successful terminal.
    EofWithoutSuccessTerminal,
    /// A prior run left this request running; its terminal is unrecoverable.
    RecoveredOldRunActive,
}

/// The downstream delivery side's outcome for a logical request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    /// The downstream response completed with a clean EOF.
    CleanEof,
    /// The client disconnected before completion.
    ClientDrop,
    /// A downstream error occurred before any bytes were sent.
    ErrorBeforeBytes,
    /// A downstream error occurred after bytes were already sent.
    ErrorAfterBytes,
    /// Delivery outcome is unknown (e.g. recovered from a prior run).
    Unknown,
}

/// Combine an execution and a delivery outcome into the single logical terminal.
///
/// A client drop is always `Canceled` and a pre-byte downstream error is always
/// `Failed`, regardless of the execution side; only then does the execution
/// outcome decide the rest. `Succeeded` requires both a stable upstream success
/// and a clean downstream EOF.
#[must_use]
pub const fn merge_logical_terminal(
    execution: ExecutionOutcome,
    delivery: DeliveryOutcome,
) -> LogicalStatus {
    match delivery {
        DeliveryOutcome::ClientDrop => LogicalStatus::Canceled,
        DeliveryOutcome::ErrorBeforeBytes => LogicalStatus::Failed,
        DeliveryOutcome::CleanEof | DeliveryOutcome::ErrorAfterBytes | DeliveryOutcome::Unknown => {
            match execution {
                ExecutionOutcome::StableSuccessTerminal => match delivery {
                    DeliveryOutcome::CleanEof => LogicalStatus::Succeeded,
                    _ => LogicalStatus::Incomplete,
                },
                ExecutionOutcome::StableFailure => LogicalStatus::Failed,
                ExecutionOutcome::TranslatorOrStreamError
                | ExecutionOutcome::EofWithoutSuccessTerminal
                | ExecutionOutcome::RecoveredOldRunActive => LogicalStatus::Incomplete,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_drop_is_canceled_regardless_of_execution() {
        for execution in [
            ExecutionOutcome::StableSuccessTerminal,
            ExecutionOutcome::StableFailure,
            ExecutionOutcome::TranslatorOrStreamError,
            ExecutionOutcome::EofWithoutSuccessTerminal,
            ExecutionOutcome::RecoveredOldRunActive,
        ] {
            assert_eq!(
                merge_logical_terminal(execution, DeliveryOutcome::ClientDrop),
                LogicalStatus::Canceled
            );
        }
    }
}
