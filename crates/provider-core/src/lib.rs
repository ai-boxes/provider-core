//! Provider contracts and proxy orchestration.

#![forbid(unsafe_code)]

pub mod account;
pub mod bounded_body;
pub mod management;
pub mod model;
pub mod protocol;
pub mod provider;
pub mod proxy;
pub mod quota;
pub mod token_count;
pub mod usage;

pub use account::{
    AccountAuthState, AccountAuthStateError, AccountId, AccountIdError, AccountRepository,
    AccountRepositoryError, AccountRuntimeState, CredentialKind, CredentialKindError,
    CredentialUpdate, CredentialWriteOutcome, NewCredential, NewProviderAccount, ProviderAccount,
    ProviderAccountAccess, ProviderAccountCreateOutcome, ProviderAccountSummary,
    ProviderAccountUpdate, ProviderKind, ProviderKindError, ProviderManagementRepository,
    ProviderSnapshot, ProviderSnapshotWriteOutcome, ProviderVisibility, ProviderVisibilityError,
    RefreshError, RefreshErrorKind, RefreshOutcome, RefreshTrigger, StoredCredential,
    StoredProviderAccount,
};
pub use bounded_body::{BoundedBodyError, collect_bounded_body};
pub use management::{
    AccountProvisioningInput, ManagedProviderDriver, PendingProviderOAuth,
    ProviderConfigurationError, ProviderControl, ProviderControlError, ProviderOAuthChallenge,
    StartedProviderOAuth,
};
pub use model::{
    DiscoveredProviderModel, ProviderModel, ProviderModelInputModality, ProviderModelOverride,
    ProviderModelPricing, ProviderModelPricingCatalog, ProviderModelPricingRecord,
    ProviderModelPricingSource, ProviderModelPricingTier, StoredProviderModel,
    validate_input_modalities,
};
pub use protocol::{PreparedProviderRequest, ProtocolBridge, ResponseTranslator, WireFormat};
pub use provider::{
    Provider, ProviderDriver, ProviderError, ProviderErrorKind, ProviderFailoverReason,
    ProviderRoute, ProviderRouteCandidate, ProviderRouter, ProviderStream, RoutableProviderModel,
};
pub use proxy::{
    PreparedProxyExecution, ProviderRequest, ProxyRequest, ProxyRequestError, ProxyService,
    RequestMetadata,
};
pub use quota::{
    ProviderQuotaControl, ProviderQuotaError, ProviderQuotaErrorKind, ProviderQuotaFetch,
    ProviderQuotaFreshness, ProviderQuotaObservation, ProviderQuotaSnapshot, ProviderQuotaSource,
    ProviderQuotaSupport, ProviderQuotaView, QuotaAmount, QuotaBreakdown, QuotaGroup,
    QuotaGroupAudience, QuotaGroupScope, QuotaMetric, QuotaMetricKind, QuotaPeriod,
    QuotaPeriodKind, QuotaScalar, QuotaUnit, merge_quota_groups,
};
pub use token_count::{TokenCountError, TokenCounter};
pub use usage::{
    BillableComponentCode, BillableObservation, BillableUnit, CacheCapability, CacheEligibility,
    CacheHit, CacheReportingExpectation, NormalizationWarning, PricingContextBasis, PricingMode,
    ProviderUsageObservation, RawUsageFields, TokenInclusionRules, TokenMetric, TokenUnknownReason,
    TotalSource, UsageContractSnapshot, counts_in_reporting_coverage, hit_from_cache_read,
    normalize_usage,
};
