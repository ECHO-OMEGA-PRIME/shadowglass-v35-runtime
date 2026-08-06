from __future__ import annotations

import json
from pathlib import Path

import cloudflare_reconcile


ROOT = Path(__file__).resolve().parents[1]


def test_deploy_gate_contains_both_forced_rollback_paths() -> None:
    script = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    assert "--force-staging-failure" in script
    assert "--force-production-failure" in script
    assert "rollback_local" in script
    assert "cloudflare_reconcile.py\" disable" in script
    assert "cloudflare_reconcile.py\" restore" in script


def test_runtime_units_never_receive_the_sovereign_key() -> None:
    for path in (ROOT / "systemd").iterdir():
        if path.is_file():
            body = path.read_text(encoding="utf-8")
            assert "sovereign" not in body.casefold()
            assert "api-read-token" not in body or "LoadCredential" in body


def test_finalizer_requires_every_gate_and_exact_route_audit() -> None:
    sql = (ROOT / "finalize_migration.sql").read_text(encoding="utf-8")
    for gate in (
        "provenance_verified",
        "forced_staging_rollback",
        "staging_smoke",
        "forced_production_rollback",
        "endpoint_verification",
        "imported_subset_verification",
        "provisioning_compatibility",
        "production_smoke",
        "consumer_canary",
        "scheduler_proof",
        "trigger_cutover",
        "active_release",
        "fresh_attestation",
    ):
        assert gate in sql
    assert "source_route_count = 17" in sql
    assert "target_route_count = 17" in sql
    assert "matched_route_count = 17" in sql
    assert "source_kind = 'endpoint-overrides'" in sql
    assert "'active_count':7" not in sql  # JSONB uses valid JSON quoting.
    assert '"active_count":7' in sql
    assert "source_kind = 'd1_imported_subset_v1'" in sql
    assert "source_kind = 'kv_imported_subset_v1'" in sql
    assert "event.source_tree = release_tree" in sql
    assert "event.source_digest = release_digest" in sql


def test_deploy_verifies_endpoints_before_applying_overrides() -> None:
    script = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    verify = script.index('"$RELEASE/verify_endpoints.py"')
    import_d1 = script.index('"$RELEASE/import_d1.py"')
    apply = script.index('"$RELEASE/apply_endpoint_overrides.py"')
    assert verify < import_d1 < apply


def test_deploy_is_git_bound_and_stages_before_production_provisioning() -> None:
    script = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    assert "status --porcelain=v1 --untracked-files=all" in script
    assert 'archive --format=tar "$RELEASE_ID"' in script
    assert 'SOURCE_TREE="$(git -C "$SOURCE_DIR" rev-parse' in script
    flow = script.index("snapshot_production")
    staging = script.index("run_staging", flow)
    forced_gate = script.index('require_gate "forced_production_rollback"', staging)
    production = script.index("provision_data", forced_gate)
    assert staging < forced_gate < production
    assert 'STAGING_DATABASE="sgv8_stage_${STAGING_SUFFIX}"' in script
    assert 'STAGING_BUCKET="shadowglass-v35-stage-${STAGING_SUFFIX}"' in script


def test_deploy_runs_real_consumer_and_scheduler_acceptance_proofs() -> None:
    script = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    assert '"$RELEASE/consumer_canary.py"' in script
    assert '--target-worker-id "$worker_id"' in script
    assert "--claim-kind acceptance_canary" in script
    assert 'systemctl start "$SCHEDULED_PROOF_UNIT"' in script
    assert 'consumer_credential_env "$CREDENTIALS"' in script
    assert 'write_receipt "consumer_canary" "passed"' in script
    assert 'write_receipt "scheduler_proof" "passed"' in script


def test_staging_consumer_uses_read_only_runtime_bind_not_home_traversal() -> None:
    script = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    function = script[
        script.index("run_staging_consumer_canary()") : script.index(
            "run_staging()", script.index("run_staging_consumer_canary()")
        )
    ]
    assert 'WorkingDirectory=$RELEASE' not in function
    assert 'BindReadOnlyPaths=$RELEASE:$runtime_path' in function
    assert '/usr/bin/env "$runtime_path/.venv/bin/python"' in function
    assert '--property=ProtectHome=tmpfs' in function
    assert '--property=ProtectSystem=strict' in function
    assert '--claim-kind acceptance_canary' in function


def test_forced_production_receipt_requires_production_injection() -> None:
    script = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    handler = script[script.index("on_error()") : script.index("write_receipt()")]
    exercise = script[
        script.index("exercise_production_rollback()") : script.index(
            "run_production_consumer_and_scheduler_proofs()"
        )
    ]
    assert "((PRODUCTION_FAILURE_INJECTED == 1))" in handler
    assert 'write_receipt "forced_production_rollback"' in handler
    assert "PRODUCTION_FAILURE_INJECTED=1" in exercise
    assert exercise.index("PRODUCTION_FAILURE_INJECTED=1") < exercise.index(
        'systemctl restart "$API_UNIT"'
    )


def test_finalizer_repeats_fresh_credential_scoped_acceptance_proofs() -> None:
    script = (ROOT / "finalize_shadowglass_v35.sh").read_text(encoding="utf-8")
    assert 'SG_DATABASE_URL_FILE="$CREDENTIALS/consumer-database-url"' in script
    assert 'systemctl start "$SCHEDULED_PROOF"' in script
    assert '--property=ExecMainStatus' in script
    assert "scheduler oneshot has no successful execution proof" not in script
    assert 'state.get("oldest_message_timestamp_ms") != 0' in script
    assert 'state.get("consumer_count") != 0' in script


def test_runtime_identities_are_split_by_responsibility() -> None:
    expected = {
        "shadowglass-v35.service": "User=shadowglass-v35-api",
        "shadowglass-v35-consumer.service": "User=shadowglass-v35-consumer",
        "shadowglass-v35-scheduled.service": "User=shadowglass-v35-scheduler",
        "shadowglass-v35-scheduled-proof.service": "User=shadowglass-v35-scheduler",
        "shadowglass-v35-consumer-proof.service": "User=shadowglass-v35-consumer",
        "shadowglass-v35-staging.service": "User=shadowglass-v35-staging",
    }
    for name, marker in expected.items():
        body = (ROOT / "systemd" / name).read_text(encoding="utf-8")
        assert marker in body


def test_cloudflare_status_summary_is_value_redacted() -> None:
    summary = cloudflare_reconcile._summary(
        {
            "queue_id": "queue-identity",
            "consumers": [{"consumer_id": "opaque", "script": cloudflare_reconcile.WORKER}],
            "matching_consumers": [{"consumer_id": "opaque", "script": cloudflare_reconcile.WORKER}],
            "metrics": {
                "backlog_count": 0,
                "backlog_bytes": 0,
                "oldest_message_timestamp_ms": 0,
            },
            "schedules": [{"cron": "0 * * * *"}],
            "domains": [],
            "subdomain": {"enabled": True},
            "content": {"legacy": True, "quarantined": False},
        }
    )
    serialized = json.dumps(summary)
    assert "opaque" not in serialized
    assert summary["matching_worker_consumers"] == 1
    assert summary["workers_dev_enabled"] is True


def test_cloudflare_consumer_restore_uses_the_documented_request_field() -> None:
    payload = cloudflare_reconcile._consumer_payload(
        {"script": cloudflare_reconcile.WORKER, "type": "worker", "settings": {"batch_size": 10}}
    )
    assert payload == {
        "script_name": cloudflare_reconcile.WORKER,
        "type": "worker",
        "settings": {"batch_size": 10},
    }


def test_cutover_uses_scoped_bearer_token_and_is_redeploy_safe() -> None:
    reconcile_source = (ROOT / "cloudflare_reconcile.py").read_text(encoding="utf-8")
    deploy = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    assert "cloudflare_shadowglass_v35_cutover_token" in reconcile_source
    assert '"Authorization": f"Bearer {key}"' in reconcile_source
    assert "X-Auth-Key" not in reconcile_source
    assert 'value.get("action") == "already_disabled"' in deploy
    assert "CF_MUTATED=0" in deploy
    assert '_cf("PUT", schedules_path' not in reconcile_source
    assert "_quarantine_content(key)" in reconcile_source


def test_finalizer_accepts_only_hash_proven_inert_grandfathered_cron() -> None:
    finalizer = (ROOT / "finalize_shadowglass_v35.sh").read_text(
        encoding="utf-8"
    )
    assert 'state.get("crons") != ["0 * * * *"]' in finalizer
    assert 'state.get("worker_quarantined") is not True' in finalizer
    assert 'state.get("worker_content_legacy") is not False' in finalizer
    assert 'state.get("worker_settings_match_backup") is not True' in finalizer
    assert 'state.get("content_backup_restoreable") is not True' in finalizer


def test_provisioning_compatibility_repeats_real_provisioners() -> None:
    script = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    function = script[script.index("verify_provisioning_compatibility()") :]
    assert '"$RELEASE/provision_credentials.py"' in function
    assert '-f - <"$RELEASE/schema.sql"' in function
    assert '"$RELEASE/import_d1.py"' in function
    assert '"$RELEASE/import_kv.py"' in function


def test_root_streams_release_sql_to_postgres_without_path_traversal() -> None:
    deploy = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    finalizer = (ROOT / "finalize_shadowglass_v35.sh").read_text(
        encoding="utf-8"
    )
    assert '-f "$RELEASE/schema.sql"' not in deploy
    assert deploy.count('-f - <"$RELEASE/schema.sql"') == 3
    assert '-f "$ACTIVE_RELEASE/finalize_migration.sql"' not in finalizer
    assert '<"$ACTIVE_RELEASE/finalize_migration.sql"' in finalizer


def test_release_modes_are_normalized_before_source_digest() -> None:
    script = (ROOT / "deploy_shadowglass_v35.sh").read_text(encoding="utf-8")
    archive = script.index('archive --format=tar "$RELEASE_ID"')
    normalize = script.index('chmod 0755 "$temporary"/*.py "$temporary"/*.sh', archive)
    digest = script.index('source_digest="$(' , normalize)
    assert archive < normalize < digest


def test_root_release_tools_never_write_python_cache_into_attested_tree() -> None:
    for name in (
        "deploy_shadowglass_v35.sh",
        "finalize_shadowglass_v35.sh",
    ):
        script = (ROOT / name).read_text(encoding="utf-8")
        assert script.startswith("#!/usr/bin/env bash\nset -Eeuo pipefail\n")
        assert "export PYTHONDONTWRITEBYTECODE=1" in script.splitlines()[:5]
