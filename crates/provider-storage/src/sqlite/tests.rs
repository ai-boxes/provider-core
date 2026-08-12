use super::*;

#[tokio::test]
async fn snapshot_update_preserves_auth_state_until_credential_revision_advances() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let account_id = AccountId::new("snapshot-auth-state").expect("account ID");
    let mut account = StoredProviderAccount {
        id: account_id.clone(),
        owner_user_id: None,
        visibility: ProviderVisibility::Private,
        provider: ProviderKind::OpenAiCompatible,
        label: "Original".to_owned(),
        group_label: "default".to_owned(),
        priority: 0,
        config_json: r#"{"base_url":"https://example.com"}"#.to_owned(),
        enabled: true,
        auth_state: AccountAuthState::Active,
        safe_error_code: None,
        created_at: 1,
        updated_at: 1,
        credential: StoredCredential {
            kind: CredentialKind::ApiKey,
            revision: 0,
            format_version: 1,
            credential_json: SecretString::from("secret"),
            expires_at: None,
            last_refreshed_at: None,
            updated_at: 1,
        },
    };
    repository
        .commit_provider_snapshot(
            ProviderSnapshot {
                account: account.clone(),
                models: Vec::new(),
                write_models: false,
                reset_models: false,
            },
            true,
            None,
        )
        .await
        .expect("create snapshot");
    repository
        .update_auth_state(
            &account_id,
            AccountAuthState::ReauthRequired,
            Some("credential_expired"),
            2,
        )
        .await
        .expect("mark reauth required");

    account.label = "Refreshed models".to_owned();
    account.updated_at = 3;
    repository
        .commit_provider_snapshot(
            ProviderSnapshot {
                account: account.clone(),
                models: Vec::new(),
                write_models: true,
                reset_models: false,
            },
            false,
            Some(0),
        )
        .await
        .expect("refresh snapshot");
    let preserved = repository
        .load_provider_account(&account_id)
        .await
        .expect("load preserved account")
        .expect("preserved account");
    assert_eq!(preserved.auth_state, AccountAuthState::ReauthRequired);
    assert_eq!(
        preserved.safe_error_code.as_deref(),
        Some("credential_expired")
    );

    account.credential.revision = 1;
    account.auth_state = AccountAuthState::Active;
    account.safe_error_code = None;
    account.updated_at = 4;
    repository
        .commit_provider_snapshot(
            ProviderSnapshot {
                account,
                models: Vec::new(),
                write_models: false,
                reset_models: false,
            },
            false,
            Some(0),
        )
        .await
        .expect("replace credential snapshot");
    let restored = repository
        .load_provider_account(&account_id)
        .await
        .expect("load restored account")
        .expect("restored account");
    assert_eq!(restored.auth_state, AccountAuthState::Active);
    assert_eq!(restored.safe_error_code, None);
    assert_eq!(restored.credential.revision, 1);
}

#[tokio::test]
async fn quota_ledger_readiness_probe_is_non_mutating() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let before = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_key_quota_ledger")
        .fetch_one(&repository.pool)
        .await
        .expect("count ledger before probe");

    repository
        .quota_ledger_ready()
        .await
        .expect("quota ledger readiness");

    let after = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_key_quota_ledger")
        .fetch_one(&repository.pool)
        .await
        .expect("count ledger after probe");
    assert_eq!(after, before);
}

#[tokio::test]
async fn password_reset_rolls_back_when_session_revocation_fails() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let user = NewUser {
        id: UserId::new("atomic-reset-user").expect("user ID"),
        username: "atomic-reset".to_owned(),
        password_hash: "old-hash".to_owned(),
        role: UserRole::SuperAdmin,
        enabled: true,
        created_at: 100,
    };
    repository
        .create_initial_user(
            user.clone(),
            test_session("atomic-reset-session", user.id.clone(), 30),
        )
        .await
        .expect("create initial user");
    sqlx::query(
        r#"
            CREATE TRIGGER reject_session_revoke
            BEFORE UPDATE OF revoked_at ON user_sessions
            BEGIN
                SELECT RAISE(ABORT, 'session revoke failed');
            END
            "#,
    )
    .execute(&repository.pool)
    .await
    .expect("install failure trigger");

    assert!(
        repository
            .reset_user_password(&user.id, "new-hash".to_owned(), 150)
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .load_user(&user.id)
            .await
            .expect("load user")
            .expect("stored user")
            .password_hash,
        "old-hash"
    );
}

#[tokio::test]
async fn provider_model_modality_check_accepts_only_unique_supported_strings() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    sqlx::query(
        r#"
            INSERT INTO provider_accounts (id, provider, label, group_label)
            VALUES ('modality-check', 'openai_compatible', 'Modality Check', 'default')
            "#,
    )
    .execute(&repository.pool)
    .await
    .expect("insert provider account");

    for (model, modalities) in [
        ("all", r#"["video","text","audio","image","pdf"]"#),
        ("subset", r#"["audio"]"#),
    ] {
        sqlx::query(
            r#"
                INSERT INTO provider_models
                    (account_id, upstream_model, input_modalities_json)
                VALUES ('modality-check', ?, ?)
                "#,
        )
        .bind(model)
        .bind(modalities)
        .execute(&repository.pool)
        .await
        .expect("valid modality array");
    }

    for (model, modalities) in [
        ("unknown", r#"["future"]"#),
        ("duplicate", r#"["text","text"]"#),
        ("non-string", "[1]"),
        ("empty", "[]"),
    ] {
        assert!(
            sqlx::query(
                r#"
                    INSERT INTO provider_models
                        (account_id, upstream_model, input_modalities_json)
                    VALUES ('modality-check', ?, ?)
                    "#,
            )
            .bind(model)
            .bind(modalities)
            .execute(&repository.pool)
            .await
            .is_err(),
            "invalid modalities {modalities} must be rejected by SQLite"
        );
    }
}

#[test]
fn stored_model_pricing_rejects_invalid_price_semantics() {
    let decode =
        |json: &str| decode_model_pricing(Some("catalog".to_owned()), Some(json.to_owned()));

    assert!(decode(
            r#"{"input":"1","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[]}"#
        )
        .is_ok());
    assert!(decode(
            r#"{"input":"1e3","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[]}"#
        )
        .is_err());
    assert!(decode(
            r#"{"input":null,"output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[]}"#
        )
        .is_err());
    assert!(decode(
            r#"{"input":"1","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[{"threshold_tokens":200000,"input":null,"output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null}]}"#
        )
        .is_err());
    assert!(decode(
            r#"{"input":"1","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null,"tiers":[{"threshold_tokens":200000,"input":"2","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null},{"threshold_tokens":200000,"input":"3","output":null,"cache_read":null,"cache_write":null,"reasoning":null,"input_audio":null,"output_audio":null}]}"#
        )
        .is_err());
}

#[tokio::test]
async fn migrates_and_compare_and_swaps_credentials() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    sqlx::query(
        r#"
            INSERT INTO provider_accounts
                (id, provider, label, group_label, enabled, auth_state)
            VALUES ('grok-main', 'grok', 'Main', 'legacy', 1, 'active')
            "#,
    )
    .execute(&repository.pool)
    .await
    .expect("insert account");
    let account_id = AccountId::new("grok-main").expect("account ID");
    let encrypted = repository
        .credential_cipher
        .encrypt(
            &account_id,
            &SecretString::from(r#"{"access_token":"old"}"#.to_owned()),
        )
        .expect("encrypt credential");
    sqlx::query(
        r#"
            INSERT INTO provider_credentials
                (account_id, credential_kind, revision, format_version, credential_json, expires_at)
            VALUES ('grok-main', 'oauth', 0, 1, ?, 100)
            "#,
    )
    .bind(encrypted)
    .execute(&repository.pool)
    .await
    .expect("insert credential");

    let accounts = repository
        .load_enabled_accounts()
        .await
        .expect("load accounts");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id.as_str(), "grok-main");
    assert_eq!(accounts[0].provider, ProviderKind::Grok);
    assert_eq!(accounts[0].credential.kind, CredentialKind::Oauth);
    assert_eq!(accounts[0].credential.revision, 0);
    assert!(accounts[0].created_at > 0);
    assert!(accounts[0].updated_at > 0);
    assert!(accounts[0].credential.updated_at > 0);

    let update = CredentialUpdate {
        expected_revision: 0,
        kind: CredentialKind::Oauth,
        format_version: 1,
        credential_json: SecretString::from(r#"{"access_token":"new"}"#.to_owned()),
        expires_at: Some(200),
        last_refreshed_at: Some(10),
        updated_at: 10,
    };
    let outcome = repository
        .compare_and_swap_credential(&accounts[0].id, update.clone())
        .await
        .expect("credential update");
    assert_eq!(outcome, CredentialWriteOutcome::Updated { revision: 1 });

    let conflict = repository
        .compare_and_swap_credential(&accounts[0].id, update)
        .await
        .expect("stale credential update");
    assert_eq!(conflict, CredentialWriteOutcome::Conflict);

    let reloaded = repository
        .load_enabled_accounts()
        .await
        .expect("reload accounts");
    assert_eq!(reloaded[0].credential.revision, 1);
    assert_eq!(
        reloaded[0].credential.credential_json.expose_secret(),
        r#"{"access_token":"new"}"#
    );
}

#[tokio::test]
async fn round_trips_codex_provider_accounts() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let owner = NewUser {
        id: UserId::new("codex-owner").expect("user ID"),
        username: "codex-owner".to_owned(),
        password_hash: "password-hash".to_owned(),
        role: UserRole::SuperAdmin,
        enabled: true,
        created_at: 1,
    };
    repository
        .create_initial_user(owner.clone(), test_session("codex-session", owner.id, 7))
        .await
        .expect("create Codex owner");
    let account_id = AccountId::new("codex-main").expect("account ID");
    let credential_json = SecretString::from(
            r#"{"type":"codex","auth_kind":"oauth","access_token":"secret","refresh_token":"refresh","id_token":"header.payload.signature","last_refreshed_at":10}"#
                .to_owned(),
        );
    let account = NewProviderAccount {
        id: account_id.clone(),
        provider: ProviderKind::Codex,
        label: "Codex Main".to_owned(),
        group_label: "default".to_owned(),
        priority: 0,
        config_json: "{}".to_owned(),
        enabled: true,
        credential: provider_core::NewCredential {
            kind: CredentialKind::Oauth,
            format_version: 1,
            credential_json: credential_json.clone(),
            expires_at: Some(100),
            last_refreshed_at: Some(10),
        },
    };

    assert_eq!(
        repository
            .create_provider_account(account, "codex-owner", ProviderVisibility::Shared)
            .await
            .expect("create Codex account"),
        ProviderAccountCreateOutcome::Created
    );
    let stored = repository
        .load_provider_account(&account_id)
        .await
        .expect("load Codex account")
        .expect("stored Codex account");

    assert_eq!(stored.provider, ProviderKind::Codex);
    assert_eq!(stored.visibility, ProviderVisibility::Shared);
    assert_eq!(stored.credential.kind, CredentialKind::Oauth);
    assert_eq!(stored.credential.expires_at, Some(100));
    assert_eq!(stored.credential.last_refreshed_at, Some(10));
    assert_eq!(
        stored.credential.credential_json.expose_secret(),
        credential_json.expose_secret()
    );
}

#[tokio::test]
async fn creates_accounts_and_preserves_model_overrides_during_sync() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let owner_user_id = UserId::new("model-owner").expect("user ID");
    repository
        .create_initial_user(
            NewUser {
                id: owner_user_id.clone(),
                username: "model-owner".to_owned(),
                password_hash: "password-hash".to_owned(),
                role: UserRole::SuperAdmin,
                enabled: true,
                created_at: 1,
            },
            test_session("model-owner-session", owner_user_id, 20),
        )
        .await
        .expect("create model owner");
    let account_id = AccountId::new("grok-models").expect("account ID");
    let account = NewProviderAccount {
        id: account_id.clone(),
        provider: ProviderKind::Grok,
        label: "Grok Models".to_owned(),
        group_label: "default".to_owned(),
        priority: 0,
        config_json: "{}".to_owned(),
        enabled: true,
        credential: provider_core::NewCredential {
            kind: CredentialKind::Oauth,
            format_version: 1,
            credential_json: SecretString::from(
                r#"{"type":"xai","auth_kind":"oauth","access_token":"secret"}"#.to_owned(),
            ),
            expires_at: None,
            last_refreshed_at: None,
        },
    };
    assert_eq!(
        repository
            .create_provider_account(account.clone(), "model-owner", ProviderVisibility::Private,)
            .await
            .expect("create account"),
        ProviderAccountCreateOutcome::Created
    );
    assert_eq!(
        repository
            .create_provider_account(account, "model-owner", ProviderVisibility::Private)
            .await
            .expect("duplicate account"),
        ProviderAccountCreateOutcome::Conflict
    );

    repository
        .synchronize_provider_models(
            &account_id,
            vec![
                DiscoveredProviderModel {
                    upstream_model: "grok-a".to_owned(),
                    input_modalities: None,
                    metadata_json: r#"{"version":1}"#.to_owned(),
                    routable: true,
                    pricing: Some(ProviderModelPricingRecord {
                        source: ProviderModelPricingSource::Catalog,
                        pricing: ProviderModelPricing {
                            input: Some("1".to_owned()),
                            output: Some("2".to_owned()),
                            cache_read: None,
                            cache_write: None,
                            reasoning: None,
                            input_audio: None,
                            output_audio: None,
                            tiers: vec![ProviderModelPricingTier {
                                threshold_tokens: 200_000,
                                input: Some("2".to_owned()),
                                output: Some("4".to_owned()),
                                cache_read: None,
                                cache_write: None,
                                reasoning: None,
                                input_audio: None,
                                output_audio: None,
                            }],
                        },
                    }),
                },
                DiscoveredProviderModel {
                    upstream_model: "grok-b".to_owned(),
                    input_modalities: Some(vec![
                        provider_core::ProviderModelInputModality::Video,
                        provider_core::ProviderModelInputModality::Image,
                    ]),
                    metadata_json: "{}".to_owned(),
                    routable: true,
                    pricing: None,
                },
            ],
            10,
        )
        .await
        .expect("initial model sync");
    assert!(
        repository
            .update_provider_model(
                &account_id,
                "grok-a",
                ProviderModelOverride {
                    alias: Some("grok-latest".to_owned()),
                    enabled: false,
                    input_modalities: Some(vec![provider_core::ProviderModelInputModality::Text,]),
                    pricing: None,
                    updated_at: 11,
                },
            )
            .await
            .expect("model override without pricing")
    );
    assert!(
        repository
            .update_provider_model(
                &account_id,
                "grok-b",
                ProviderModelOverride {
                    alias: Some("grok-b-latest".to_owned()),
                    enabled: true,
                    input_modalities: Some(vec![
                        provider_core::ProviderModelInputModality::Video,
                        provider_core::ProviderModelInputModality::Image,
                    ]),
                    pricing: None,
                    updated_at: 11,
                },
            )
            .await
            .expect("alias-only model override")
    );
    let catalog_model = repository
        .list_provider_models(Some(&account_id))
        .await
        .expect("catalog model after override")
        .into_iter()
        .find(|model| model.upstream_model == "grok-a")
        .expect("grok-a after override");
    assert_eq!(
        catalog_model
            .pricing
            .expect("catalog pricing remains")
            .pricing
            .tiers
            .len(),
        1,
        "an alias/status-only edit must preserve catalog tiers"
    );

    let repriced_models = repository
        .synchronize_provider_models(
            &account_id,
            vec![
                DiscoveredProviderModel {
                    upstream_model: "grok-a".to_owned(),
                    input_modalities: None,
                    metadata_json: r#"{"version":1}"#.to_owned(),
                    routable: true,
                    pricing: Some(ProviderModelPricingRecord {
                        source: ProviderModelPricingSource::Catalog,
                        pricing: ProviderModelPricing {
                            input: Some("5".to_owned()),
                            output: Some("6".to_owned()),
                            cache_read: None,
                            cache_write: None,
                            reasoning: None,
                            input_audio: None,
                            output_audio: None,
                            tiers: vec![ProviderModelPricingTier {
                                threshold_tokens: 200_000,
                                input: Some("7".to_owned()),
                                output: Some("8".to_owned()),
                                cache_read: None,
                                cache_write: None,
                                reasoning: None,
                                input_audio: None,
                                output_audio: None,
                            }],
                        },
                    }),
                },
                DiscoveredProviderModel {
                    upstream_model: "grok-b".to_owned(),
                    input_modalities: Some(vec![
                        provider_core::ProviderModelInputModality::Audio,
                        provider_core::ProviderModelInputModality::Pdf,
                    ]),
                    metadata_json: "{}".to_owned(),
                    routable: true,
                    pricing: None,
                },
            ],
            12,
        )
        .await
        .expect("catalog repricing sync");
    let repriced = repriced_models
        .iter()
        .find(|model| model.upstream_model == "grok-a")
        .expect("repriced grok-a")
        .pricing
        .as_ref()
        .expect("repriced catalog value");
    assert_eq!(repriced.source, ProviderModelPricingSource::Catalog);
    assert_eq!(repriced.pricing.input.as_deref(), Some("5"));
    assert_eq!(repriced.pricing.tiers[0].output.as_deref(), Some("8"));
    assert_eq!(
        repriced_models
            .iter()
            .find(|model| model.upstream_model == "grok-b")
            .expect("refreshed grok-b")
            .input_modalities,
        Some(vec![
            provider_core::ProviderModelInputModality::Audio,
            provider_core::ProviderModelInputModality::Pdf,
        ]),
        "editing only the alias must not freeze discovered input modalities"
    );

    assert!(
        repository
            .update_provider_model(
                &account_id,
                "grok-a",
                ProviderModelOverride {
                    alias: Some("grok-latest".to_owned()),
                    enabled: false,
                    input_modalities: Some(vec![provider_core::ProviderModelInputModality::Text,]),
                    pricing: Some(Some(ProviderModelPricing {
                        input: Some("3".to_owned()),
                        output: Some("4".to_owned()),
                        cache_read: None,
                        cache_write: None,
                        reasoning: None,
                        input_audio: None,
                        output_audio: None,
                        tiers: Vec::new(),
                    })),
                    updated_at: 12,
                },
            )
            .await
            .expect("model override and manual pricing")
    );

    let models = repository
        .synchronize_provider_models(
            &account_id,
            vec![
                DiscoveredProviderModel {
                    upstream_model: "grok-a".to_owned(),
                    input_modalities: Some(vec![
                        provider_core::ProviderModelInputModality::Text,
                        provider_core::ProviderModelInputModality::Image,
                    ]),
                    metadata_json: r#"{"version":2}"#.to_owned(),
                    routable: true,
                    pricing: Some(ProviderModelPricingRecord {
                        source: ProviderModelPricingSource::Catalog,
                        pricing: ProviderModelPricing {
                            input: Some("10".to_owned()),
                            output: Some("20".to_owned()),
                            cache_read: None,
                            cache_write: None,
                            reasoning: None,
                            input_audio: None,
                            output_audio: None,
                            tiers: Vec::new(),
                        },
                    }),
                },
                DiscoveredProviderModel {
                    upstream_model: "grok-c".to_owned(),
                    input_modalities: None,
                    metadata_json: "{}".to_owned(),
                    routable: true,
                    pricing: None,
                },
            ],
            20,
        )
        .await
        .expect("second model sync");

    let model_a = models
        .iter()
        .find(|model| model.upstream_model == "grok-a")
        .expect("grok-a");
    assert_eq!(model_a.alias.as_deref(), Some("grok-latest"));
    assert!(!model_a.enabled);
    assert!(model_a.available);
    assert_eq!(model_a.metadata_json, r#"{"version":2}"#);
    assert_eq!(
        model_a.input_modalities,
        Some(vec![provider_core::ProviderModelInputModality::Text]),
        "model synchronization must preserve manually configured input modalities"
    );
    assert_eq!(
        model_a.pricing,
        Some(ProviderModelPricingRecord {
            source: ProviderModelPricingSource::Manual,
            pricing: ProviderModelPricing {
                input: Some("3".to_owned()),
                output: Some("4".to_owned()),
                cache_read: None,
                cache_write: None,
                reasoning: None,
                input_audio: None,
                output_audio: None,
                tiers: Vec::new(),
            },
        }),
        "model synchronization must preserve manual pricing"
    );
    assert!(
        !models
            .iter()
            .find(|model| model.upstream_model == "grok-b")
            .expect("grok-b")
            .available
    );
    assert!(
        models
            .iter()
            .find(|model| model.upstream_model == "grok-c")
            .expect("grok-c")
            .available
    );
    assert!(
        repository
            .update_provider_model(
                &account_id,
                "grok-a",
                ProviderModelOverride {
                    alias: None,
                    enabled: true,
                    input_modalities: None,
                    pricing: Some(None),
                    updated_at: 21,
                },
            )
            .await
            .expect("clear model pricing")
    );
    assert_eq!(
        repository
            .list_provider_models(Some(&account_id))
            .await
            .expect("models after clearing pricing")
            .into_iter()
            .find(|model| model.upstream_model == "grok-a")
            .expect("grok-a after clearing pricing")
            .pricing,
        None
    );
}

#[tokio::test]
async fn initial_setup_is_single_use_and_claims_existing_providers() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    sqlx::query(
        r#"
            INSERT INTO provider_accounts
                (id, provider, label, group_label, enabled, auth_state)
            VALUES ('existing-grok', 'grok', 'Existing Grok', 'legacy', 1, 'active')
            "#,
    )
    .execute(&repository.pool)
    .await
    .expect("insert existing provider");

    let initial_user = NewUser {
        id: UserId::new("user-initial").expect("user ID"),
        username: "admin".to_owned(),
        password_hash: "password-hash".to_owned(),
        role: UserRole::SuperAdmin,
        enabled: true,
        created_at: 100,
    };
    assert_eq!(
        repository
            .create_initial_user(
                initial_user.clone(),
                test_session("initial-session", initial_user.id.clone(), 10),
            )
            .await
            .expect("create initial user"),
        InitialUserCreateOutcome::Created
    );
    let second_user = NewUser {
        id: UserId::new("user-second").expect("user ID"),
        username: "second".to_owned(),
        ..initial_user
    };
    assert_eq!(
        repository
            .create_initial_user(
                second_user.clone(),
                test_session("second-session", second_user.id, 12),
            )
            .await
            .expect("reject second initial user"),
        InitialUserCreateOutcome::AlreadyConfigured
    );

    let row = sqlx::query(
        "SELECT owner_user_id, visibility FROM provider_accounts WHERE id = 'existing-grok'",
    )
    .fetch_one(&repository.pool)
    .await
    .expect("load claimed provider");
    assert_eq!(
        row.try_get::<String, _>("owner_user_id")
            .expect("provider owner"),
        "user-initial"
    );
    assert_eq!(
        row.try_get::<String, _>("visibility")
            .expect("provider visibility"),
        "private"
    );
    assert!(
        repository
            .load_user_by_username("second")
            .await
            .expect("load user")
            .is_none()
    );
    assert!(
        repository
            .load_session_by_token_hash(&[10; 32])
            .await
            .expect("load initial session")
            .is_some()
    );
}

#[tokio::test]
async fn opaque_session_can_be_loaded_and_revoked() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let user_id = UserId::new("user-session").expect("user ID");
    assert_eq!(
        repository
            .create_initial_user(
                NewUser {
                    id: user_id.clone(),
                    username: "admin".to_owned(),
                    password_hash: "password-hash".to_owned(),
                    role: UserRole::SuperAdmin,
                    enabled: true,
                    created_at: 100,
                },
                test_session("initial-session", user_id.clone(), 10),
            )
            .await
            .expect("create initial user"),
        InitialUserCreateOutcome::Created
    );
    repository
        .create_session(NewSession {
            id: SessionId::new("session-one").expect("session ID"),
            user_id,
            token_hash: [1; 32],
            expires_at: 300,
            created_at: 100,
        })
        .await
        .expect("create session");
    let session = repository
        .load_session_by_token_hash(&[1; 32])
        .await
        .expect("load session")
        .expect("session");
    assert_eq!(session.token_hash, [1; 32]);
    assert_eq!(session.expires_at, 300);
    assert!(
        repository
            .revoke_session(&session.id, 150)
            .await
            .expect("revoke")
    );
    assert_eq!(
        repository
            .load_session_by_token_hash(&[1; 32])
            .await
            .expect("load revoked session")
            .expect("revoked session")
            .revoked_at,
        Some(150)
    );
}

#[tokio::test]
async fn disabling_user_atomically_revokes_sessions_and_permanently_disables_keys() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let user_id = UserId::new("disabled-user").expect("user ID");
    repository
        .create_initial_user(
            NewUser {
                id: user_id.clone(),
                username: "admin".to_owned(),
                password_hash: "password-hash".to_owned(),
                role: UserRole::SuperAdmin,
                enabled: true,
                created_at: 100,
            },
            test_session("disabled-user-session", user_id.clone(), 9),
        )
        .await
        .expect("create initial user");
    sqlx::query(
        r#"
            INSERT INTO api_keys
                (id, owner_user_id, group_label, label, key,
                 enabled, spent_atoms, created_at, updated_at)
            VALUES ('disabled-user-key', ?, 'group', 'key', 'pode-disabled-user-key',
                    1, '0', 100, 100)
            "#,
    )
    .bind(user_id.as_str())
    .execute(&repository.pool)
    .await
    .expect("create API key");

    assert!(
        repository
            .set_user_enabled(&user_id, false, 200)
            .await
            .expect("disable user")
    );
    let state = sqlx::query(
        r#"
            SELECT u.enabled, s.revoked_at, k.enabled AS key_enabled
            FROM users AS u
            INNER JOIN user_sessions AS s ON s.user_id = u.id
            INNER JOIN api_keys AS k ON k.owner_user_id = u.id
            WHERE u.id = ?
            "#,
    )
    .bind(user_id.as_str())
    .fetch_one(&repository.pool)
    .await
    .expect("load disabled state");
    assert_eq!(state.try_get::<i64, _>("enabled").expect("user enabled"), 0);
    assert_eq!(
        state.try_get::<i64, _>("revoked_at").expect("revoked at"),
        200
    );
    assert_eq!(
        state.try_get::<i64, _>("key_enabled").expect("key enabled"),
        0
    );

    assert!(
        repository
            .set_user_enabled(&user_id, true, 300)
            .await
            .expect("re-enable user")
    );
    let key_enabled =
        sqlx::query_scalar::<_, i64>("SELECT enabled FROM api_keys WHERE id = 'disabled-user-key'")
            .fetch_one(&repository.pool)
            .await
            .expect("load API key state");
    assert_eq!(key_enabled, 0);
}

#[tokio::test]
async fn quota_admission_allows_remaining_spend_and_rejects_exhausted_keys() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let user_id = UserId::new("quota-user").expect("user ID");
    repository
        .create_initial_user(
            NewUser {
                id: user_id.clone(),
                username: "quota-admin".to_owned(),
                password_hash: "password-hash".to_owned(),
                role: UserRole::SuperAdmin,
                enabled: true,
                created_at: 1,
            },
            test_session("quota-session", user_id.clone(), 1),
        )
        .await
        .expect("create quota user");
    let key_id = ApiKeyId::new("quota-key").expect("API key ID");
    sqlx::query(
        r#"
            INSERT INTO api_keys (
                id, owner_user_id, group_label, label, key,
                enabled, quota_limit_atoms, spent_atoms, created_at, updated_at
            )
            VALUES (?, ?, 'group', 'quota', 'pode-quota-key', 1, '100', '0', 1, 1)
            "#,
    )
    .bind(key_id.as_str())
    .bind(user_id.as_str())
    .execute(&repository.pool)
    .await
    .expect("create quota key");

    let (left, right) = tokio::join!(
        repository.admit_api_key_quota(&key_id),
        repository.admit_api_key_quota(&key_id),
    );
    assert_eq!(
        left.expect("left admission"),
        QuotaAdmissionOutcome::Admitted
    );
    assert_eq!(
        right.expect("right admission"),
        QuotaAdmissionOutcome::Admitted
    );

    sqlx::query("UPDATE api_keys SET spent_atoms = '99' WHERE id = ?")
        .bind(key_id.as_str())
        .execute(&repository.pool)
        .await
        .expect("set remaining spend");
    assert_eq!(
        repository
            .admit_api_key_quota(&key_id)
            .await
            .expect("boundary admission"),
        QuotaAdmissionOutcome::Admitted
    );

    sqlx::query("UPDATE api_keys SET spent_atoms = '100' WHERE id = ?")
        .bind(key_id.as_str())
        .execute(&repository.pool)
        .await
        .expect("exhaust quota");
    assert_eq!(
        repository
            .admit_api_key_quota(&key_id)
            .await
            .expect("exhausted admission"),
        QuotaAdmissionOutcome::Exceeded
    );

    sqlx::query("UPDATE api_keys SET spent_atoms = '150' WHERE id = ?")
        .bind(key_id.as_str())
        .execute(&repository.pool)
        .await
        .expect("overshoot spend");
    assert_eq!(
        repository
            .admit_api_key_quota(&key_id)
            .await
            .expect("overspent admission"),
        QuotaAdmissionOutcome::Exceeded
    );

    sqlx::query("UPDATE api_keys SET quota_limit_atoms = NULL, spent_atoms = '0' WHERE id = ?")
        .bind(key_id.as_str())
        .execute(&repository.pool)
        .await
        .expect("clear quota limit");
    assert_eq!(
        repository
            .admit_api_key_quota(&key_id)
            .await
            .expect("unlimited admission"),
        QuotaAdmissionOutcome::Unlimited
    );

    sqlx::query("UPDATE api_keys SET quota_limit_atoms = '100' WHERE id = ?")
        .bind(key_id.as_str())
        .execute(&repository.pool)
        .await
        .expect("restore quota limit");
    sqlx::query(
        r#"
            INSERT INTO api_key_quota_ledger (
                entry_id, api_key_id, reserved_atoms, state, reserved_at_ms, dispatched_at_ms
            ) VALUES ('ambiguous', ?, '0', 'reserved', 1, 2)
            "#,
    )
    .bind(key_id.as_str())
    .execute(&repository.pool)
    .await
    .expect("insert unresolved dispatched claim");
    assert_eq!(
        repository
            .admit_api_key_quota(&key_id)
            .await
            .expect("ambiguous claim admission"),
        QuotaAdmissionOutcome::Admitted
    );
}

#[tokio::test]
async fn registration_codes_are_one_time_and_survive_username_conflicts() {
    let repository = SqliteAccountRepository::in_memory()
        .await
        .expect("in-memory repository");
    let admin = NewUser {
        id: UserId::new("registration-admin").expect("admin ID"),
        username: "admin".to_owned(),
        password_hash: "admin-password-hash".to_owned(),
        role: UserRole::SuperAdmin,
        enabled: true,
        created_at: 100,
    };
    assert_eq!(
        repository
            .create_initial_user(
                admin.clone(),
                test_session("registration-admin-session", admin.id.clone(), 10),
            )
            .await
            .expect("create admin"),
        InitialUserCreateOutcome::Created
    );
    repository
        .create_registration_code(NewRegistrationCode {
            code_hash: [20; 32],
            expires_at: 200,
        })
        .await
        .expect("create registration code");
    assert!(
        repository
            .registration_code_valid(&[20; 32], 199)
            .await
            .expect("validate unexpired registration code")
    );
    assert!(
        !repository
            .registration_code_valid(&[20; 32], 200)
            .await
            .expect("reject registration code at expiry")
    );

    let conflict = NewUser {
        id: UserId::new("conflicting-registration").expect("user ID"),
        username: "ADMIN".to_owned(),
        password_hash: "password-hash".to_owned(),
        role: UserRole::User,
        enabled: true,
        created_at: 120,
    };
    assert_eq!(
        repository
            .register_user(
                &[20; 32],
                conflict.clone(),
                test_session("conflicting-registration-session", conflict.id, 20),
                120,
            )
            .await
            .expect("reject username conflict"),
        RegisterUserOutcome::Conflict
    );

    let member = NewUser {
        id: UserId::new("registered-member").expect("user ID"),
        username: "member".to_owned(),
        password_hash: "password-hash".to_owned(),
        role: UserRole::User,
        enabled: true,
        created_at: 121,
    };
    assert_eq!(
        repository
            .register_user(
                &[20; 32],
                member.clone(),
                test_session("registered-member-session", member.id.clone(), 22),
                121,
            )
            .await
            .expect("register member"),
        RegisterUserOutcome::Created
    );
    assert!(
        repository
            .load_user(&member.id)
            .await
            .expect("load registered member")
            .is_some()
    );
    assert_eq!(
        repository
            .register_user(
                &[20; 32],
                NewUser {
                    id: UserId::new("reused-registration").expect("user ID"),
                    username: "other".to_owned(),
                    password_hash: "password-hash".to_owned(),
                    role: UserRole::User,
                    enabled: true,
                    created_at: 122,
                },
                test_session(
                    "reused-registration-session",
                    UserId::new("reused-registration").expect("user ID"),
                    24,
                ),
                122,
            )
            .await
            .expect("reject reused code"),
        RegisterUserOutcome::InvalidCode
    );
}

fn test_session(id: &str, user_id: UserId, token_hash: u8) -> NewSession {
    NewSession {
        id: SessionId::new(id).expect("session ID"),
        user_id,
        token_hash: [token_hash; 32],
        expires_at: 300,
        created_at: 100,
    }
}
