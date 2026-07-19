use std::sync::LazyLock;

use provider_core::ProviderModel;

struct ModelDefinition {
    id: &'static str,
    created: u64,
}

const MODEL_DEFINITIONS: &[ModelDefinition] = &[
    ModelDefinition {
        id: "grok-build-0.1",
        created: 1_779_321_600,
    },
    ModelDefinition {
        id: "grok-4.5",
        created: 1_783_526_400,
    },
    ModelDefinition {
        id: "grok-4.3",
        created: 1_775_606_400,
    },
    ModelDefinition {
        id: "grok-4.20-0309-reasoning",
        created: 1_773_014_400,
    },
    ModelDefinition {
        id: "grok-4.20-0309-non-reasoning",
        created: 1_773_014_400,
    },
    ModelDefinition {
        id: "grok-4.20-multi-agent-0309",
        created: 1_773_014_400,
    },
    ModelDefinition {
        id: "grok-3-mini",
        created: 1_740_960_000,
    },
    ModelDefinition {
        id: "grok-3-mini-fast",
        created: 1_740_960_000,
    },
    ModelDefinition {
        id: "grok-composer-2.5-fast",
        created: 1_740_960_000,
    },
];

static MODELS: LazyLock<Vec<ProviderModel>> = LazyLock::new(|| {
    MODEL_DEFINITIONS
        .iter()
        .map(|definition| ProviderModel::new(definition.id, "xai").with_created(definition.created))
        .collect()
});

#[must_use]
pub fn grok_models() -> &'static [ProviderModel] {
    &MODELS
}
