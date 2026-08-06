#!/usr/bin/env bash
set -Eeuo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=/home/forge/shadowglass-v35
CURRENT="$ROOT/current"
UNIT=shadowglass-v35.service
CONSUMER=shadowglass-v35-consumer.service
TIMER=shadowglass-v35-scheduled.timer
SCHEDULED=shadowglass-v35-scheduled.service
CONSUMER_PROOF=shadowglass-v35-consumer-proof.service
SCHEDULED_PROOF=shadowglass-v35-scheduled-proof.service
CREDENTIALS=/etc/echo/credentials/shadowglass-v35
RECOVERY_MARKER="$ROOT/RECOVERY_REQUIRED.json"

[[ $EUID -eq 0 ]] || { echo "finalization requires root" >&2; exit 2; }
exec 9>/run/lock/shadowglass-v35.lock
flock -n 9 || { echo "another ShadowGlass v35 deployment holds the release lock" >&2; exit 2; }
[[ ! -e "$RECOVERY_MARKER" ]] || { echo "unresolved Cloudflare recovery marker blocks finalization" >&2; exit 3; }
ACTIVE_RELEASE="$(readlink -f "$CURRENT")"
case "$ACTIVE_RELEASE" in
  "$ROOT"/releases/*) ;;
  *) echo "invalid active release" >&2; exit 3 ;;
esac
RELEASE_ID="${ACTIVE_RELEASE##*/}"
[[ "$RELEASE_ID" =~ ^[0-9a-f]{40}$ ]] || { echo "active release is not a Git commit" >&2; exit 3; }
SOURCE_TREE="$(<"$ACTIVE_RELEASE/.release-git-tree")"
SOURCE_DIGEST="$(<"$ACTIVE_RELEASE/.release-source.sha256")"
[[ "$SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] || { echo "release Git tree is invalid" >&2; exit 3; }
[[ "$SOURCE_DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "release source digest is invalid" >&2; exit 3; }
ACTUAL_DIGEST="$(
  tar -C "$ACTIVE_RELEASE" --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    --exclude=.venv --exclude=.release-source.sha256 --exclude=.release-git-tree -cf - . |
    sha256sum | awk '{print $1}'
)"
[[ "$ACTUAL_DIGEST" == "$SOURCE_DIGEST" ]] || { echo "active release bytes differ from Git attestation" >&2; exit 3; }
for unit in "$UNIT" "$CONSUMER" "$TIMER"; do
  systemctl is-active --quiet "$unit" || { echo "required unit is inactive: $unit" >&2; exit 3; }
done
for unit in shadowglass-v35.service shadowglass-v35-consumer.service \
            "$SCHEDULED" shadowglass-v35-scheduled.timer \
            "$CONSUMER_PROOF" "$SCHEDULED_PROOF"; do
  cmp -s "/etc/systemd/system/$unit" "$ACTIVE_RELEASE/systemd/$unit" || {
    echo "installed unit differs from attested release: $unit" >&2; exit 3;
  }
  [[ "$(systemctl show "$unit" --property=NeedDaemonReload --value)" == "no" ]] || {
    echo "systemd manager has not loaded the attested unit: $unit" >&2; exit 3;
  }
done
if systemctl is-failed --quiet "$SCHEDULED"; then
  echo "installed production scheduler is failed" >&2
  exit 3
fi
STATUS_JSON="$("$ACTIVE_RELEASE/.venv/bin/python" "$ACTIVE_RELEASE/cloudflare_reconcile.py" status)"
STATUS_JSON="$STATUS_JSON" "$ACTIVE_RELEASE/.venv/bin/python" - <<'PY'
import json
import os

state = json.loads(os.environ["STATUS_JSON"])
if (
    state.get("backlog_count") != 0
    or state.get("backlog_bytes") != 0
    or state.get("oldest_message_timestamp_ms") != 0
):
    raise SystemExit("legacy queue backlog is not empty")
if (
    state.get("consumer_count") != 0
    or state.get("matching_worker_consumers") != 0
):
    raise SystemExit("legacy Cloudflare queue consumer remains active")
if state.get("crons") != ["0 * * * *"]:
    raise SystemExit("grandfathered legacy cron identity changed")
if (
    state.get("worker_quarantined") is not True
    or state.get("worker_content_legacy") is not False
):
    raise SystemExit("legacy Cloudflare Worker content is not proven quarantined")
if state.get("worker_settings_match_backup") is not True:
    raise SystemExit("live Worker settings differ from the recovery backup")
if state.get("workers_dev_enabled"):
    raise SystemExit("legacy workers.dev edge remains active")
if state.get("custom_domain_count") != 0:
    raise SystemExit("legacy custom-domain edge remains active")
if state.get("backup_restoreable") is not True:
    raise SystemExit("legacy trigger backup is not strictly restoreable")
if state.get("content_backup_restoreable") is not True:
    raise SystemExit("legacy Worker content backup is not strictly restoreable")
PY

ATTESTATION_DIR="$(mktemp -d "$ROOT/.fresh-attestation.XXXXXX")"
trap 'rm -rf -- "$ATTESTATION_DIR"' EXIT
printf '%s\n' "$STATUS_JSON" >"$ATTESTATION_DIR/cloudflare-status.json"
"$ACTIVE_RELEASE/.venv/bin/python" "$ACTIVE_RELEASE/smoke_live.py" \
  --base http://127.0.0.1:8470 \
  --read-token-file "$CREDENTIALS/api-read-token" \
  --write-token-file "$CREDENTIALS/api-write-token" \
  --smoke-token-file "$CREDENTIALS/api-smoke-token" >"$ATTESTATION_DIR/smoke.json"
env \
  SG_RELAY_URL_FILE="$CREDENTIALS/relay-url" \
  SG_RELAY_ALLOWED_HOSTS_FILE="$CREDENTIALS/relay-allowed-hosts" \
  SG_MINIO_ENDPOINT_FILE="$CREDENTIALS/minio-endpoint" \
  SG_MINIO_ACCESS_KEY_FILE="$CREDENTIALS/minio-access-key" \
  SG_MINIO_SECRET_KEY_FILE="$CREDENTIALS/minio-secret-key" \
  SG_MINIO_BUCKET_FILE="$CREDENTIALS/minio-bucket" \
  "$ACTIVE_RELEASE/.venv/bin/python" "$ACTIVE_RELEASE/verify_endpoints.py" \
  >"$ATTESTATION_DIR/endpoints.json"
"$ACTIVE_RELEASE/.venv/bin/python" "$ACTIVE_RELEASE/import_d1.py" \
  --dsn-file "$CREDENTIALS/migration-database-url" \
  >"$ATTESTATION_DIR/d1-subset.json"
"$ACTIVE_RELEASE/.venv/bin/python" "$ACTIVE_RELEASE/import_kv.py" \
  --dsn-file "$CREDENTIALS/migration-database-url" \
  --owned-key-sha256 0ed4aba4fcb9e90290e6705b478271578df07711f7c8c406250573f4580ecbc1 \
  --owned-key-sha256 6ab5dd227af217d945a270e0b36e34a09b77661ad78fe8e32d4e3e14e0c5736d \
  >"$ATTESTATION_DIR/kv-subset.json"
"$ACTIVE_RELEASE/.venv/bin/python" "$ACTIVE_RELEASE/apply_endpoint_overrides.py" \
  --dsn-file "$CREDENTIALS/migration-database-url" \
  >"$ATTESTATION_DIR/endpoint-reconciliation.json"
env \
  SG_DATABASE_URL_FILE="$CREDENTIALS/consumer-database-url" \
  SG_MINIO_ENDPOINT_FILE="$CREDENTIALS/minio-endpoint" \
  SG_MINIO_ACCESS_KEY_FILE="$CREDENTIALS/minio-access-key" \
  SG_MINIO_SECRET_KEY_FILE="$CREDENTIALS/minio-secret-key" \
  SG_MINIO_BUCKET_FILE="$CREDENTIALS/minio-bucket" \
  "$ACTIVE_RELEASE/.venv/bin/python" "$ACTIVE_RELEASE/consumer_canary.py" \
    --target-worker-id forge-shadowglass-v35 --timeout-seconds 90 \
    >"$ATTESTATION_DIR/consumer.json"
systemctl reset-failed "$SCHEDULED_PROOF" >/dev/null 2>&1 || true
systemctl start "$SCHEDULED_PROOF"
[[ "$(systemctl show "$SCHEDULED_PROOF" --property=Result --value)" == "success" ]]
[[ "$(systemctl show "$SCHEDULED_PROOF" --property=ExecMainStatus --value)" == "0" ]]
systemctl show "$SCHEDULED_PROOF" --property=Id --property=ActiveState \
  --property=Result --property=ExecMainStatus --property=NeedDaemonReload \
  >"$ATTESTATION_DIR/scheduler.txt"
systemctl show "$CONSUMER" "$TIMER" "$SCHEDULED" "$CONSUMER_PROOF" \
  --property=Id --property=ActiveState --property=UnitFileState --property=NeedDaemonReload \
  >"$ATTESTATION_DIR/units.txt"
printf '%s\n' "$SOURCE_TREE" >"$ATTESTATION_DIR/source-tree"
printf '%s\n' "$SOURCE_DIGEST" >"$ATTESTATION_DIR/source-digest"
ATTESTATION_SHA="$(
  tar -C "$ATTESTATION_DIR" --sort=name --mtime='@0' --owner=0 --group=0 \
    --numeric-owner -cf - . | sha256sum | awk '{print $1}'
)"
FINALIZE_ATTEMPT_ID="$(</proc/sys/kernel/random/uuid)"
OCCURRED_AT="$(date --utc +%Y-%m-%dT%H:%M:%S.%NZ)"
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d echo \
  -v attempt="$FINALIZE_ATTEMPT_ID" -v rid="$RELEASE_ID" \
  -v tree="$SOURCE_TREE" -v digest="$SOURCE_DIGEST" \
  -v occurred="$OCCURRED_AT" -v sha="$ATTESTATION_SHA" -f - >/dev/null <<'SQL'
INSERT INTO cf_shadowglass_v35.deployment_events
  (attempt_id, gate, release_id, source_tree, source_digest, status, evidence_sha256, occurred_at)
VALUES (:'attempt'::uuid, 'fresh_attestation', :'rid', :'tree', :'digest', 'passed', :'sha', :'occurred'::timestamptz);
INSERT INTO cf_shadowglass_v35.deployment_receipts
  (gate, release_id, source_tree, source_digest, status, evidence_sha256, occurred_at)
VALUES ('fresh_attestation', :'rid', :'tree', :'digest', 'passed', :'sha', :'occurred'::timestamptz)
ON CONFLICT (gate) DO UPDATE SET
  release_id = EXCLUDED.release_id,
  source_tree = EXCLUDED.source_tree,
  source_digest = EXCLUDED.source_digest,
  status = EXCLUDED.status,
  evidence_sha256 = EXCLUDED.evidence_sha256,
  occurred_at = EXCLUDED.occurred_at,
  completed_at = clock_timestamp();
SQL

sudo -u forge /usr/bin/python3 /home/forge/cf-migration-audit/audit_rollup.py >/dev/null
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d echo \
  -v active_release="$ACTIVE_RELEASE" -v source_tree="$SOURCE_TREE" \
  -v source_digest="$SOURCE_DIGEST" -f - \
  <"$ACTIVE_RELEASE/finalize_migration.sql" >/dev/null
sudo -u forge /usr/bin/python3 /home/forge/cf-migration-audit/audit_rollup.py >/dev/null
echo '{"ok":true,"gate":"migration_finalized"}'
