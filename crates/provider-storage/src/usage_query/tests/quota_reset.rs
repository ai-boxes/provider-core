use super::*;

#[tokio::test]
async fn latest_zero_or_low_usage_does_not_leave_an_active_window_exhausted() {
    for used in [0, 1, 100, 499] {
        let repository = setup().await;
        observe(&repository, "primary", 20, 10000, 60).await;
        observe(&repository, "primary", 30, used, 60).await;
        assert!(points(&repository, 45).await.is_empty());
        let ended = points(&repository, 60).await;
        assert_eq!(ended.len(), 1);
        assert_eq!(
            ended[0].used_hundredths,
            if used == 0 { 10000 } else { used as u64 }
        );
    }
}

#[tokio::test]
async fn same_second_reset_preserves_the_positive_predecessor_and_latest_zero() {
    let repository = setup().await;
    observe(&repository, "primary", 30, 100, 60).await;
    observe(&repository, "primary", 30, 0, 80).await;
    observe(&repository, "primary", 45, 10000, 80).await;
    observe(&repository, "primary", 45, 0, 80).await;
    let result = points(&repository, 45).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].used_hundredths, 100);
    assert_eq!(result[0].next_window_end_ms, Some(T0 + 80 * 60_000));
    assert_eq!(result[0].estimated_limit_cost.as_atoms(), 2_900_000);
}

async fn setup() -> SqliteUsageRepository {
    let repository = repository().await;
    sqlx::query("INSERT INTO provider_accounts (id, provider, label, group_label, config_json, priority) VALUES ('account-1', 'codex', 'Codex', 'codex', '{}', 0)")
        .execute(&mut *repository.write.lock().await).await.expect("account");
    sqlx::query("INSERT INTO provider_credentials (account_id, credential_kind, revision, format_version, credential_json) VALUES ('account-1', 'oauth', 1, 1, 'v1:test')")
        .execute(&mut *repository.write.lock().await).await.expect("credential");
    for (id, offset, atoms) in [
        ("before", 10, 20_000),
        ("gap", 25, 9_000),
        ("after", 40, 10_000),
    ] {
        let mut attempt = Written::new(id, "user-1", T0 + offset * 60_000);
        attempt.cost.total_known = UsdAtoms::from_atoms(atoms);
        write(&repository, &attempt).await;
    }
    repository
}

async fn observe(
    repository: &SqliteUsageRepository,
    metric: &str,
    minute: i64,
    used: i64,
    end: i64,
) {
    sqlx::query("INSERT INTO provider_quota_window_observations (account_id, credential_revision, credential_identity_revision, observed_at_ms, group_key, metric_key, metric_position, used_hundredths, period_kind, starts_at_ms, ends_at_ms, duration_seconds) VALUES ('account-1', 1, 0, ?, 'codex', ?, 0, ?, 'rolling', ?, ?, 3600)")
        .bind(T0 + minute * 60_000).bind(metric).bind(used)
        .bind(T0 + (end - 60) * 60_000).bind(T0 + end * 60_000)
        .execute(&mut *repository.write.lock().await).await.expect("observation");
}

async fn points(
    repository: &SqliteUsageRepository,
    minute: i64,
) -> Vec<provider_usage::QuotaLimitEstimatePoint> {
    repository
        .provider_quota_estimates(
            &["account-1".to_owned()],
            TimeRange::new(T0, T0 + minute * 60_000).expect("range"),
        )
        .await
        .expect("estimates")
}

#[tokio::test]
async fn early_reset_closes_old_window_and_isolates_new_cost_per_metric() {
    let repository = setup().await;
    observe(&repository, "primary", 20, 5000, 60).await;
    observe(&repository, "weekly", 20, 5000, 60).await;
    observe(&repository, "primary", 30, 0, 80).await;
    observe(&repository, "primary", 45, 10000, 80).await;
    observe(&repository, "weekly", 45, 6000, 60).await;
    assert!(points(&repository, 29).await.is_empty());
    let closed = points(&repository, 30).await;
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].observed_cost.as_atoms(), 20_000);
    assert_eq!(closed[0].estimated_limit_cost.as_atoms(), 40_000);
    assert_eq!(closed[0].window_end_ms, T0 + 30 * 60_000);
    assert_eq!(closed[0].next_window_end_ms, Some(T0 + 80 * 60_000));
    let current = points(&repository, 45).await;
    assert_eq!(current.len(), 2);
    let new = current
        .iter()
        .find(|point| point.window_end_ms == T0 + 80 * 60_000)
        .unwrap();
    assert_eq!(new.window_start_ms, T0 + 30 * 60_000);
    assert_eq!(new.observed_cost.as_atoms(), 10_000);
    assert!(new.sampling_incomplete);
    assert_eq!(new.dispatched_attempts, 1);
    let ended = points(&repository, 80).await;
    assert_eq!(ended.len(), 3);
    let weekly = ended
        .iter()
        .find(|point| point.metric_key == "weekly")
        .unwrap();
    assert_eq!(weekly.observed_cost.as_atoms(), 39_000);
    assert!(!weekly.sampling_incomplete);
    sqlx::query("UPDATE provider_credentials SET quota_identity_revision = 1")
        .execute(&mut *repository.write.lock().await)
        .await
        .unwrap();
    assert!(points(&repository, 80).await.is_empty());
}

#[tokio::test]
async fn reset_requires_zero_usage_changed_boundary_and_an_unexpired_predecessor() {
    for (used, end, minute) in [(0, 60, 30), (100, 80, 30), (0, 120, 60)] {
        let repository = setup().await;
        observe(&repository, "primary", 20, 5000, 60).await;
        observe(&repository, "primary", minute, used, end).await;
        let result = points(&repository, minute).await;
        assert!(
            result
                .iter()
                .all(|point| point.next_window_end_ms.is_none())
        );
        assert!(result.iter().all(|point| !point.sampling_incomplete));
    }
}

#[tokio::test]
async fn insertion_order_does_not_change_reset_detection() {
    let repository = setup().await;
    observe(&repository, "primary", 45, 10000, 80).await;
    observe(&repository, "primary", 30, 0, 80).await;
    observe(&repository, "primary", 20, 5000, 60).await;
    let result = points(&repository, 45).await;
    assert_eq!(result.len(), 2);
    assert!(
        result
            .iter()
            .any(|point| point.next_window_end_ms.is_some())
    );
    assert!(result.iter().any(|point| point.sampling_incomplete));
}

#[tokio::test]
async fn repeated_resets_keep_separate_cycles_and_exclude_cross_boundary_attempts() {
    let repository = setup().await;
    observe(&repository, "primary", 20, 5000, 60).await;
    observe(&repository, "primary", 30, 0, 80).await;
    observe(&repository, "primary", 45, 5000, 80).await;
    observe(&repository, "primary", 50, 0, 90).await;
    observe(&repository, "primary", 55, 10000, 90).await;
    let mut after = Written::new("second-reset", "user-1", T0 + 54 * 60_000);
    after.cost.total_known = UsdAtoms::from_atoms(5_000);
    write(&repository, &after).await;
    let mut crossing = Written::new("crossing", "user-1", T0 + 53 * 60_000);
    crossing.cost.total_known = UsdAtoms::from_atoms(7_000);
    write(&repository, &crossing).await;
    sqlx::query(
        "UPDATE usage_attempts SET started_at_ms = ? WHERE logical_request_id = 'crossing'",
    )
    .bind(T0 + 49 * 60_000)
    .execute(&mut *repository.write.lock().await)
    .await
    .unwrap();
    let result = points(&repository, 55).await;
    assert_eq!(result.len(), 3);
    let last = result
        .iter()
        .find(|point| point.window_end_ms == T0 + 90 * 60_000)
        .unwrap();
    assert_eq!(last.observed_cost.as_atoms(), 5_000);
    assert_eq!(last.window_start_ms, T0 + 50 * 60_000);
    assert!(last.sampling_incomplete);
}
