//! Attempt- and logical-level status vocabulary.
//!
//! Dispatch evidence is three-state: it records what actually happened by the
//! terminal, never a pre-dispatch "intent to call". A commitment/maybe-invoked
//! distinction is deliberately out of scope for the first version; anything the
//! process could not resolve becomes a [`TrackingState::Gap`], not a false
//! "confirmed".

use serde::{Deserialize, Serialize};

/// Evidence that an attempt actually reached the upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchEvidence {
    /// The transport send gate was never crossed: prepare failed, or the
    /// attempt was cancelled/aborted before sending.
    NotInvoked,
    /// The dispatch future was first polled across the transport send gate.
    /// Merely constructing an un-polled future does not count. This still does
    /// not prove the socket was written or the provider received the request.
    DispatchInvoked,
    /// An upstream HTTP response or stream was observed.
    ResponseObserved,
}

impl DispatchEvidence {
    /// Whether this attempt counts as a confirmed dispatch invocation for the
    /// resource-usage scope. `NotInvoked` is a pre-dispatch failure and is
    /// excluded.
    #[must_use]
    pub const fn is_confirmed_dispatch(self) -> bool {
        matches!(self, Self::DispatchInvoked | Self::ResponseObserved)
    }
}

/// Terminal status of a logical request. Only the lifecycle reducer may commit a
/// terminal value; `InProgress` is the sole non-terminal state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalStatus {
    InProgress,
    Succeeded,
    Failed,
    Canceled,
    Incomplete,
}

impl LogicalStatus {
    /// Whether this is a committed terminal status (everything except
    /// `InProgress`).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::InProgress)
    }
}

/// One attempt's position within its logical request, starting at 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AttemptSequence(pub u32);

/// Why local tracking has a known gap for a fact. Orthogonal to dispatch
/// evidence and logical status: a gap records that bookkeeping was lost, not
/// that the proxy request itself failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackingGapReason {
    /// A persistence write failed and the fact was kept only in memory.
    WriteFailed,
    /// The bounded writer was saturated and shed the event.
    WriterSaturated,
    /// A prior run left this in-flight; recovery cannot reconstruct its terminal.
    RecoveredInFlight,
    /// A cancel raced with the first dispatch poll and the outcome is unprovable.
    AmbiguousCancel,
    /// The response could not be inspected, so its usage was never seen. This is
    /// not the same as a response that carried no usage: here the absence is ours,
    /// not the provider's, and it must not read as "reported nothing".
    ObservationLost,
}

/// Whether the expected lifecycle writes for a fact completed, or a known gap
/// occurred while the proxy kept running.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TrackingState {
    Complete,
    Gap { reason: TrackingGapReason },
}
