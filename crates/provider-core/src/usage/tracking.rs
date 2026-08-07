//! The seam between layers that observe usage facts and the layer that records
//! them.
//!
//! These are traits rather than concrete types so that `provider-core` stays
//! below the usage implementation: the runtime and the protocol layer only need
//! to *report* what they saw, and the crate that owns pricing, normalization and
//! persistence implements the receiving end.
//!
//! Both traits return nothing and cannot fail. Reporting a usage fact must never
//! be able to change, delay, or fail a proxy response.

use std::sync::Arc;

use crate::{
    ProviderKind, ProviderModelPricingRecord,
    usage::{RawUsageFields, UsageContractSnapshot},
};

/// What the usage layer needs in order to interpret one provider's responses.
///
/// A driver returns this only once its wire contract has been established from
/// real responses. `None` means usage is not tracked for that provider, which is
/// an honest gap rather than a guessed contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderUsageProfile {
    pub provider: ProviderKind,
    pub contract: UsageContractSnapshot,
}

/// One logical request's tracking handle, created after authentication.
pub trait RequestTracking: Send + Sync {
    /// Open an attempt for one upstream call.
    ///
    /// Called once per real call, so a refresh-and-retry produces two attempts.
    /// Returns `None` when nothing is being tracked, letting callers keep a
    /// single code path.
    fn begin_attempt(
        &self,
        profile: ProviderUsageProfile,
        account_id: &str,
        configured_model: Option<&str>,
        pricing: Option<&ProviderModelPricingRecord>,
    ) -> Option<Arc<dyn AttemptTracking>>;
}

/// One upstream call's tracking.
///
/// Each method reports something that was actually observed, and the recorded
/// dispatch evidence is derived from which ones were called. Callers never set an
/// evidence level directly, so they cannot claim more than they saw. An attempt
/// that is dropped without any terminal call is recorded as an unprovable
/// cancellation rather than as a call that never happened.
pub trait AttemptTracking: Send + Sync {
    /// The call returned a stream to read, so the provider answered.
    fn stream_opened(&self);

    /// The first output token was observed on the upstream stream.
    fn first_token_observed(&self);

    /// The upstream stream reached its documented successful terminal.
    ///
    /// Without this an ended stream is only known to have ended, which is
    /// `incomplete` rather than a success.
    fn success_terminal_observed(&self);

    /// The provider named the model it actually served.
    ///
    /// Prices are resolved from the model the attempt was *prepared for*, so a
    /// provider that served a different one makes the estimate wrong. Only the
    /// provider's own answer can reveal that, which is why this is reported
    /// rather than assumed. Called at most once per attempt in practice; a
    /// repeat is ignored rather than overwriting the first answer.
    fn provider_model_observed(&self, model: &str);

    /// The response could not be inspected, so its usage was never seen.
    ///
    /// Distinct from a response that carried no usage: here the absence is ours,
    /// and recording it as "reported nothing" would be a false claim.
    fn observation_lost(&self);

    /// The response ended. `fields` is the usage it carried, or `None` if it
    /// carried none.
    ///
    /// Terminal, and applied exactly once: a stream that ends and is then dropped
    /// must not record the attempt twice, which would double-count usage.
    fn finished(&self, fields: Option<RawUsageFields>);

    /// The call failed outright, with no stream to read. Terminal.
    ///
    /// `answered` distinguishes a provider that replied with a failure status —
    /// which proves it received the request — from a transport failure, which
    /// proves only that the send was attempted.
    fn failed(&self, answered: bool);
}
