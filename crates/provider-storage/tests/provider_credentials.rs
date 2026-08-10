use std::time::{SystemTime, UNIX_EPOCH};

use provider_auth::{AuthRepository, NewSession, NewUser, SessionId, UserId, UserRole};
use provider_core::{
    AccountAuthState, AccountId, CredentialKind, ProviderManagementRepository, ProviderSnapshot,
    ProviderSnapshotWriteOutcome, ProviderVisibility, StoredCredential, StoredProviderAccount,
};
use provider_storage::SqliteAccountRepository;
use secrecy::{ExposeSecret, SecretString};
use sqlx::{ConnectOptions, Row, SqlitePool, sqlite::SqliteConnectOptions};

#[tokio::test]
async fn stores_only_v1_ciphertext_and_fails_closed_with_the_wrong_key() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "provider-credential-test-{}-{unique}.db",
        std::process::id()
    ));
    let repository = SqliteAccountRepository::connect(&path, [0x5a; 32])
        .await
        .expect("repository");
    let owner_id = UserId::new("credential-owner").expect("owner ID");
    repository
        .create_initial_user(
            NewUser {
                id: owner_id.clone(),
                username: "credential-owner".to_owned(),
                password_hash: "password-hash".to_owned(),
                role: UserRole::SuperAdmin,
                enabled: true,
                created_at: 1,
            },
            NewSession {
                id: SessionId::new("credential-session").expect("session ID"),
                user_id: owner_id.clone(),
                token_hash: [7; 32],
                expires_at: 300,
                created_at: 1,
            },
        )
        .await
        .expect("owner");
    let account_id = AccountId::new("encrypted-provider").expect("account ID");
    let plaintext =
        SecretString::from(r#"{"auth_kind":"api_key","api_key":"upstream-secret"}"#.to_owned());
    let created = repository
        .commit_provider_snapshot(
            ProviderSnapshot {
                account: StoredProviderAccount {
                    id: account_id.clone(),
                    owner_user_id: Some(owner_id.as_str().to_owned()),
                    visibility: ProviderVisibility::Private,
                    provider: provider_core::ProviderKind::OpenAiCompatible,
                    label: "Encrypted".to_owned(),
                    group_label: "default".to_owned(),
                    config_json: r#"{"base_url":"https://api.example.com/v1"}"#.to_owned(),
                    enabled: true,
                    auth_state: AccountAuthState::Active,
                    safe_error_code: None,
                    created_at: 1,
                    updated_at: 1,
                    credential: StoredCredential {
                        kind: CredentialKind::ApiKey,
                        revision: 0,
                        format_version: 1,
                        credential_json: plaintext.clone(),
                        expires_at: None,
                        last_refreshed_at: None,
                        updated_at: 1,
                    },
                },
                models: Vec::new(),
                write_models: true,
                reset_models: true,
            },
            true,
            None,
        )
        .await
        .expect("create provider");
    assert!(matches!(
        created,
        ProviderSnapshotWriteOutcome::Committed { .. }
    ));

    let options = SqliteConnectOptions::new()
        .filename(&path)
        .read_only(true)
        .disable_statement_logging();
    let pool = SqlitePool::connect_with(options)
        .await
        .expect("inspection pool");
    let row = sqlx::query("SELECT credential_json FROM provider_credentials WHERE account_id = ?")
        .bind(account_id.as_str())
        .fetch_one(&pool)
        .await
        .expect("ciphertext row");
    let ciphertext: String = row.try_get("credential_json").expect("ciphertext");
    assert!(ciphertext.starts_with("v1:"));
    assert!(!ciphertext.contains("upstream-secret"));
    pool.close().await;

    let stored = repository
        .load_provider_account(&account_id)
        .await
        .expect("load provider")
        .expect("provider");
    assert_eq!(
        stored.credential.credential_json.expose_secret(),
        plaintext.expose_secret()
    );
    drop(repository);

    let wrong_key = SqliteAccountRepository::connect(&path, [0xa5; 32])
        .await
        .expect("wrong-key repository opens");
    let error = wrong_key
        .load_provider_account(&account_id)
        .await
        .expect_err("wrong key must not return plaintext");
    assert!(
        error
            .to_string()
            .contains("failed to decrypt provider credential")
    );
}
