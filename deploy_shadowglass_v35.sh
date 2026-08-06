#!/usr/bin/env bash
set -Eeuo pipefail
export PYTHONDONTWRITEBYTECODE=1

SERVICE="shadowglass-v35"
ROOT="/home/forge/shadowglass-v35"
CREDENTIALS="/etc/echo/credentials/shadowglass-v35"
STAGING_CREDENTIALS="/etc/echo/credentials/shadowglass-v35-staging"
SOURCE_DIR="${SG_SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
RELEASE_ID="${SG_RELEASE_ID:-}"
SOURCE_TREE=""
MODE="deploy"
SKIP_CLOUDFLARE=0
API_UNIT="${SERVICE}.service"
CONSUMER_UNIT="${SERVICE}-consumer.service"
SCHEDULED_UNIT="${SERVICE}-scheduled.service"
TIMER_UNIT="${SERVICE}-scheduled.timer"
CONSUMER_PROOF_UNIT="${SERVICE}-consumer-proof.service"
SCHEDULED_PROOF_UNIT="${SERVICE}-scheduled-proof.service"
STAGING_UNIT="${SERVICE}-staging.service"
STAGING_CONSUMER_UNIT="${SERVICE}-staging-consumer.service"
UNITS=("$API_UNIT" "$CONSUMER_UNIT" "$SCHEDULED_UNIT" "$TIMER_UNIT" \
       "$CONSUMER_PROOF_UNIT" "$SCHEDULED_PROOF_UNIT")
OWNED_KV_HASHES=(
  "0ed4aba4fcb9e90290e6705b478271578df07711f7c8c406250573f4580ecbc1"
  "6ab5dd227af217d945a270e0b36e34a09b77661ad78fe8e32d4e3e14e0c5736d"
)

usage() {
  echo "usage: $0 [--deploy|--stage-only|--force-staging-failure|--force-production-failure] [--skip-cloudflare]" >&2
}

while (($#)); do
  case "$1" in
    --deploy) MODE="deploy" ;;
    --stage-only) MODE="stage-only" ;;
    --force-staging-failure) MODE="force-staging-failure" ;;
    --force-production-failure) MODE="force-production-failure" ;;
    --skip-cloudflare) SKIP_CLOUDFLARE=1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || { echo "deployment requires root" >&2; exit 2; }
[[ -f "$SOURCE_DIR/migration_contract.json" ]] || { echo "invalid source directory" >&2; exit 2; }
git -C "$SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "source directory must be a Git worktree" >&2; exit 2;
}
SOURCE_HEAD="$(git -C "$SOURCE_DIR" rev-parse --verify HEAD)"
[[ "$SOURCE_HEAD" =~ ^[0-9a-f]{40}$ ]] || { echo "source HEAD is invalid" >&2; exit 2; }
if [[ -n "$RELEASE_ID" && "$RELEASE_ID" != "$SOURCE_HEAD" ]]; then
  echo "SG_RELEASE_ID does not match source HEAD" >&2
  exit 2
fi
RELEASE_ID="$SOURCE_HEAD"
[[ -z "$(git -C "$SOURCE_DIR" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "source worktree must be clean before deployment" >&2; exit 2;
}
SOURCE_TREE="$(git -C "$SOURCE_DIR" rev-parse --verify "${RELEASE_ID}^{tree}")"
[[ "$SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] || { echo "source tree identity is invalid" >&2; exit 2; }
exec 9>/run/lock/shadowglass-v35.lock
flock -n 9 || { echo "another ShadowGlass v35 deployment holds the release lock" >&2; exit 2; }

mkdir -p "$ROOT"
[[ ! -e "$ROOT/RECOVERY_REQUIRED.json" ]] || {
  echo "unresolved Cloudflare recovery marker blocks deployment; run verified restore" >&2
  exit 2
}
RELEASE="$ROOT/releases/$RELEASE_ID"
CANDIDATE="$ROOT/candidate"
CURRENT="$ROOT/current"
ROLLBACK_DIR="$(mktemp -d "$ROOT/.rollback.XXXXXX")"
DEPLOY_ATTEMPT_ID="$(</proc/sys/kernel/random/uuid)"
STAGING_INSTALLED=0
PROMOTED=0
CF_MUTATED=0
ROLLBACK_RUNNING=0
STAGING_SUFFIX="${RELEASE_ID:0:12}"
STAGING_DATABASE="sgv35_stage_${STAGING_SUFFIX}"
STAGING_BUCKET="shadowglass-v35-stage-${STAGING_SUFFIX}"
STAGING_RESOURCES=0
STAGING_FORCED_FAILURE=0
PRODUCTION_FAILURE_INJECTED=0

cleanup_staging_resources() {
  systemctl stop "$STAGING_CONSUMER_UNIT" >/dev/null 2>&1 || true
  systemctl reset-failed "$STAGING_CONSUMER_UNIT" >/dev/null 2>&1 || true
  systemctl stop "$STAGING_UNIT" >/dev/null 2>&1 || true
  if ((STAGING_INSTALLED)); then
    rm -f "/etc/systemd/system/$STAGING_UNIT"
    systemctl daemon-reload
    STAGING_INSTALLED=0
  fi
  if ((STAGING_RESOURCES)); then
    "$RELEASE/.venv/bin/python" "$RELEASE/provision_credentials.py" \
      --bindings /mnt/cf_kv_r2/workers/shadowglass-v35/bindings.json \
      --directory "$STAGING_CREDENTIALS" --mode staging-cleanup \
      --staging-database "$STAGING_DATABASE" --staging-bucket "$STAGING_BUCKET" \
      >/dev/null
    STAGING_RESOURCES=0
  fi
  [[ ! -e "$STAGING_CREDENTIALS" ]]
}

cleanup() {
  cleanup_staging_resources || echo "staging resource cleanup requires attention" >&2
  rm -rf -- "$ROLLBACK_DIR"
}
trap cleanup EXIT

atomic_link() {
  local target="$1" link="$2" temporary
  temporary="${link}.new.$$"
  rm -f -- "$temporary"
  ln -s -- "$target" "$temporary"
  mv -Tf -- "$temporary" "$link"
}

unit_state() {
  local unit="$1"
  printf '%s|%s\n' \
    "$(systemctl is-active "$unit" 2>/dev/null || true)" \
    "$(systemctl is-enabled "$unit" 2>/dev/null || true)"
}

snapshot_production() {
  local unit
  if [[ -L "$CURRENT" ]]; then
    readlink -f "$CURRENT" >"$ROLLBACK_DIR/current-target"
  fi
  for unit in "${UNITS[@]}"; do
    unit_state "$unit" >"$ROLLBACK_DIR/$unit.state"
    if [[ -f "/etc/systemd/system/$unit" ]]; then
      cp -a "/etc/systemd/system/$unit" "$ROLLBACK_DIR/$unit.file"
    fi
  done
  tar -C "$ROLLBACK_DIR" --sort=name --mtime='@0' --owner=0 --group=0 \
    --numeric-owner --exclude=snapshot-evidence -cf - . | sha256sum | awk '{print $1}' \
    >"$ROLLBACK_DIR/snapshot-evidence"
}

restore_unit_state() {
  local unit="$1" active enabled
  IFS='|' read -r active enabled <"$ROLLBACK_DIR/$unit.state"
  systemctl unmask "$unit" >/dev/null 2>&1 || true
  case "$enabled" in
    enabled|enabled-runtime) systemctl enable "$unit" >/dev/null 2>&1 || true ;;
    masked|masked-runtime) systemctl mask "$unit" >/dev/null 2>&1 || true ;;
    disabled) systemctl disable "$unit" >/dev/null 2>&1 || true ;;
  esac
  if [[ "$active" == "active" ]]; then
    systemctl start "$unit"
  else
    systemctl stop "$unit" >/dev/null 2>&1 || true
  fi
}

verify_production_snapshot() {
  local unit expected actual previous
  if [[ -f "$ROLLBACK_DIR/current-target" ]]; then
    [[ -L "$CURRENT" ]] || return 1
    previous="$(<"$ROLLBACK_DIR/current-target")"
    [[ "$(readlink -f "$CURRENT")" == "$previous" ]] || return 1
  else
    [[ ! -e "$CURRENT" && ! -L "$CURRENT" ]] || return 1
  fi
  for unit in "${UNITS[@]}"; do
    expected="$(<"$ROLLBACK_DIR/$unit.state")"
    actual="$(unit_state "$unit")"
    [[ "$actual" == "$expected" ]] || return 1
    if [[ -f "$ROLLBACK_DIR/$unit.file" ]]; then
      cmp -s "$ROLLBACK_DIR/$unit.file" "/etc/systemd/system/$unit" || return 1
    else
      [[ ! -e "/etc/systemd/system/$unit" ]] || return 1
    fi
  done
}

rollback_local() {
  local unit
  ((PROMOTED)) || return 0
  ((ROLLBACK_RUNNING == 0)) || return 0
  ROLLBACK_RUNNING=1
  systemctl stop "${UNITS[@]}" >/dev/null 2>&1 || true
  for unit in "${UNITS[@]}"; do
    if [[ -f "$ROLLBACK_DIR/$unit.file" ]]; then
      cp -a "$ROLLBACK_DIR/$unit.file" "/etc/systemd/system/$unit"
    else
      rm -f "/etc/systemd/system/$unit"
    fi
  done
  if [[ -f "$ROLLBACK_DIR/current-target" ]]; then
    atomic_link "$(<"$ROLLBACK_DIR/current-target")" "$CURRENT"
  else
    rm -f "$CURRENT"
  fi
  systemctl daemon-reload
  for unit in "${UNITS[@]}"; do
    restore_unit_state "$unit"
  done
  verify_production_snapshot
  if [[ -f "$ROLLBACK_DIR/current-target" ]] && \
     grep -q '^active|' "$ROLLBACK_DIR/$API_UNIT.state"; then
    wait_health "http://127.0.0.1:8470"
  fi
  PROMOTED=0
  ROLLBACK_RUNNING=0
}

on_error() {
  local rc=$? restore_rc=0
  trap - ERR
  set +e
  if ((CF_MUTATED)); then
    "$RELEASE/.venv/bin/python" "$RELEASE/cloudflare_reconcile.py" restore || restore_rc=$?
    if ((restore_rc == 0)); then
      "$RELEASE/.venv/bin/python" "$RELEASE/cloudflare_reconcile.py" status \
        >"$ROOT/cloudflare-restored-${RELEASE_ID}.json" || restore_rc=$?
    fi
    if ((restore_rc != 0)); then
      printf '{"attempt_id":"%s","release_id":"%s","state":"cloudflare_restore_required"}\n' \
        "$DEPLOY_ATTEMPT_ID" "$RELEASE_ID" >"$ROOT/RECOVERY_REQUIRED.json"
      chmod 0600 "$ROOT/RECOVERY_REQUIRED.json"
      sync -f "$ROOT/RECOVERY_REQUIRED.json"
      echo "Cloudflare restore did not converge; recovery marker persisted" >&2
      exit "$restore_rc"
    fi
    CF_MUTATED=0
  fi
  if ((PROMOTED)); then
    rollback_local
  fi
  if [[ "$MODE" == "force-production-failure" ]] && \
     ((PRODUCTION_FAILURE_INJECTED == 1)) && \
     verify_production_snapshot && \
     write_receipt "forced_production_rollback" "rolled_back" "$ROLLBACK_DIR/snapshot-evidence"; then
    echo '{"ok":true,"gate":"forced_production_rollback"}'
    exit 0
  fi
  exit "$rc"
}

write_receipt() {
  local gate="$1" status="$2" evidence="${3:-}" receipt source_digest evidence_digest occurred
  mkdir -p "$ROOT/receipts"
  receipt="$ROOT/receipts/${RELEASE_ID}-${DEPLOY_ATTEMPT_ID}-${gate}.json"
  source_digest="$(<"$RELEASE/.release-source.sha256")"
  evidence_digest="$source_digest"
  if [[ -n "$evidence" ]]; then
    [[ -f "$evidence" ]] || { echo "gate evidence is missing: $gate" >&2; return 1; }
    evidence_digest="$(sha256sum "$evidence" | awk '{print $1}')"
  fi
  occurred="$(date --utc +%Y-%m-%dT%H:%M:%S.%NZ)"
  printf '{"attempt_id":"%s","evidence_sha256":"%s","gate":"%s","occurred_at":"%s","release_id":"%s","source_digest":"%s","source_tree":"%s","status":"%s"}\n' \
    "$DEPLOY_ATTEMPT_ID" "$evidence_digest" "$gate" "$occurred" "$RELEASE_ID" "$source_digest" "$SOURCE_TREE" "$status" >"$receipt"
  chmod 0600 "$receipt"
  sync -f "$receipt"
  sync -f "$ROOT/receipts"
}

sync_receipt_to_db() {
  local receipt="$1" gate status attempt occurred sha
  read -r attempt gate status occurred sha < <(
    "$RELEASE/.venv/bin/python" - "$receipt" "$RELEASE_ID" "$SOURCE_TREE" \
      "$(<"$RELEASE/.release-source.sha256")" <<'PY'
import datetime, json, pathlib, re, sys
p = json.loads(pathlib.Path(sys.argv[1]).read_text())
if p.get("release_id") != sys.argv[2] or p.get("source_tree") != sys.argv[3] or p.get("source_digest") != sys.argv[4]:
    raise SystemExit("receipt lineage mismatch")
if not re.fullmatch(r"[0-9a-f-]{36}", str(p.get("attempt_id", ""))):
    raise SystemExit("receipt attempt identity mismatch")
if not re.fullmatch(r"[a-z0-9_]+", str(p.get("gate", ""))):
    raise SystemExit("receipt gate identity mismatch")
if p.get("status") not in {"passed", "rolled_back"}:
    raise SystemExit("receipt status mismatch")
if not re.fullmatch(r"[0-9a-f]{64}", str(p.get("evidence_sha256", ""))):
    raise SystemExit("receipt evidence digest mismatch")
try:
    occurred = datetime.datetime.fromisoformat(str(p["occurred_at"]).replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as exc:
    raise SystemExit("receipt occurrence timestamp mismatch") from exc
if occurred.tzinfo is None:
    raise SystemExit("receipt occurrence timestamp must be timezone-aware")
print(p["attempt_id"], p["gate"], p["status"], p["occurred_at"], p["evidence_sha256"])
PY
  )
  sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d echo \
    -v attempt="$attempt" -v gate="$gate" -v rid="$RELEASE_ID" \
    -v tree="$SOURCE_TREE" -v digest="$(<"$RELEASE/.release-source.sha256")" \
    -v occurred="$occurred" -v status="$status" -v sha="$sha" -f - \
    >/dev/null <<'SQL'
INSERT INTO cf_shadowglass_v35.deployment_events
  (attempt_id, gate, release_id, source_tree, source_digest, status, evidence_sha256, occurred_at)
VALUES (:'attempt'::uuid, :'gate', :'rid', :'tree', :'digest', :'status', :'sha', :'occurred'::timestamptz)
ON CONFLICT (attempt_id, gate, release_id) DO NOTHING;
INSERT INTO cf_shadowglass_v35.deployment_receipts
  (gate, release_id, source_tree, source_digest, status, evidence_sha256, occurred_at)
VALUES (:'gate', :'rid', :'tree', :'digest', :'status', :'sha', :'occurred'::timestamptz)
ON CONFLICT (gate) DO UPDATE SET
  release_id = EXCLUDED.release_id,
  source_tree = EXCLUDED.source_tree,
  source_digest = EXCLUDED.source_digest,
  status = EXCLUDED.status,
  evidence_sha256 = EXCLUDED.evidence_sha256,
  occurred_at = EXCLUDED.occurred_at,
  completed_at = clock_timestamp();
SQL
}

sync_release_receipts() {
  local receipt
  shopt -s nullglob
  for receipt in "$ROOT/receipts/${RELEASE_ID}"-*.json; do
    sync_receipt_to_db "$receipt"
  done
  shopt -u nullglob
}

require_gate() {
  local gate="$1" status="$2"
  "$RELEASE/.venv/bin/python" - "$ROOT/receipts" "$RELEASE_ID" "$SOURCE_TREE" \
    "$(<"$RELEASE/.release-source.sha256")" "$gate" "$status" <<'PY'
import datetime, json, pathlib, re, sys
root, release, tree, digest, gate, status = sys.argv[1:]
for path in pathlib.Path(root).glob(f"{release}-*.json"):
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        continue
    if (value.get("release_id"), value.get("source_tree"), value.get("source_digest"), value.get("gate"), value.get("status")) != (release, tree, digest, gate, status):
        continue
    if not re.fullmatch(r"[0-9a-f]{64}", str(value.get("evidence_sha256", ""))):
        continue
    try:
        occurred = datetime.datetime.fromisoformat(str(value["occurred_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        continue
    if occurred.tzinfo is not None:
        raise SystemExit(0)
raise SystemExit(f"required release-bound gate is missing: {gate}={status}")
PY
}

prepare_release() {
  local temporary source_digest release_digest
  mkdir -p "$ROOT/releases"
  if [[ ! -d "$RELEASE" ]]; then
    temporary="$ROOT/releases/.${RELEASE_ID}.tmp"
    rm -rf -- "$temporary"
    mkdir -p "$temporary"
    # The release is extracted from the reviewed commit object, never copied
    # from mutable working-directory bytes (including ignored files).
    git -C "$SOURCE_DIR" archive --format=tar "$RELEASE_ID" | tar -C "$temporary" -xf -
    # Normalize runtime modes before hashing. The Git tree remains the exact
    # source-mode identity; this digest attests the installed normalized tree.
    find "$temporary" -type d -exec chmod 0755 {} +
    find "$temporary" -type f -exec chmod 0644 {} +
    chmod 0755 "$temporary"/*.py "$temporary"/*.sh
    source_digest="$(
      tar -C "$temporary" --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
        --exclude=.release-source.sha256 --exclude=.release-git-tree -cf - . |
        sha256sum | awk '{print $1}'
    )"
    printf '%s\n' "$source_digest" >"$temporary/.release-source.sha256"
    printf '%s\n' "$SOURCE_TREE" >"$temporary/.release-git-tree"
    python3 -m venv --system-site-packages "$temporary/.venv"
    "$temporary/.venv/bin/python" -m pip install --disable-pip-version-check -q \
      -r "$temporary/requirements.txt" -r "$temporary/requirements-dev.txt"
    PYTHONPYCACHEPREFIX="$temporary/.venv/pycache" \
      "$temporary/.venv/bin/python" -m pytest -q -p no:cacheprovider "$temporary/tests"
    "$temporary/.venv/bin/ruff" check --no-cache "$temporary"
    PYTHONPYCACHEPREFIX="$temporary/.venv/pycache" \
      "$temporary/.venv/bin/python" -m py_compile \
      "$temporary"/{app,core,storage,relay,scraper,object_store,queue_worker,consumer_canary,scheduled_job,import_d1,import_kv,apply_endpoint_overrides,verify_endpoints,service,smoke_live,verify_recovered_contract,provision_credentials,cloudflare_reconcile}.py
    PYTHONPYCACHEPREFIX="$temporary/.venv/pycache" \
      "$temporary/.venv/bin/python" "$temporary/verify_recovered_contract.py"
    chown -R root:root "$temporary"
    find "$temporary" -path "$temporary/.venv" -prune -o -type d -exec chmod 0755 {} +
    find "$temporary" -path "$temporary/.venv" -prune -o -type f -exec chmod u=rw,go=r {} +
    chmod 0755 "$temporary"/*.py "$temporary"/*.sh
    mv "$temporary" "$RELEASE"
  else
    [[ -f "$RELEASE/.release-source.sha256" ]] || { echo "existing release has no source attestation" >&2; exit 1; }
    [[ -f "$RELEASE/.release-git-tree" ]] || { echo "existing release has no Git tree attestation" >&2; exit 1; }
    [[ "$(<"$RELEASE/.release-git-tree")" == "$SOURCE_TREE" ]] || { echo "existing release Git tree differs from source" >&2; exit 1; }
  fi
  source_digest="$(<"$RELEASE/.release-source.sha256")"
  release_digest="$(
    tar -C "$RELEASE" --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
      --exclude=.venv --exclude=.release-source.sha256 --exclude=.release-git-tree -cf - . |
      sha256sum | awk '{print $1}'
  )"
  [[ "$release_digest" == "$source_digest" ]] || { echo "release content digest mismatch" >&2; exit 1; }
  PYTHONPYCACHEPREFIX="$RELEASE/.venv/pycache" \
    "$RELEASE/.venv/bin/python" -m pytest -q -p no:cacheprovider "$RELEASE/tests"
  "$RELEASE/.venv/bin/ruff" check --no-cache "$RELEASE"
  PYTHONPYCACHEPREFIX="$RELEASE/.venv/pycache" \
    "$RELEASE/.venv/bin/python" "$RELEASE/verify_recovered_contract.py"
  atomic_link "$RELEASE" "$CANDIDATE"
}

create_staging_user() {
  id shadowglass-v35-staging >/dev/null 2>&1 || \
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin shadowglass-v35-staging
}

create_production_users() {
  local user
  for user in shadowglass-v35-api shadowglass-v35-consumer shadowglass-v35-scheduler; do
    id "$user" >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$user"
  done
}

credential_env() {
  local directory="$1"
  shift
  env \
    SG_DATABASE_URL_FILE="$directory/database-url" \
    SG_RELAY_URL_FILE="$directory/relay-url" \
    SG_RELAY_ALLOWED_HOSTS_FILE="$directory/relay-allowed-hosts" \
    SG_MINIO_ENDPOINT_FILE="$directory/minio-endpoint" \
    SG_MINIO_ACCESS_KEY_FILE="$directory/minio-access-key" \
    SG_MINIO_SECRET_KEY_FILE="$directory/minio-secret-key" \
    SG_MINIO_BUCKET_FILE="$directory/minio-bucket" "$@"
}

consumer_credential_env() {
  local directory="$1"
  shift
  env \
    SG_DATABASE_URL_FILE="$directory/consumer-database-url" \
    SG_RELAY_URL_FILE="$directory/relay-url" \
    SG_RELAY_ALLOWED_HOSTS_FILE="$directory/relay-allowed-hosts" \
    SG_MINIO_ENDPOINT_FILE="$directory/minio-endpoint" \
    SG_MINIO_ACCESS_KEY_FILE="$directory/minio-access-key" \
    SG_MINIO_SECRET_KEY_FILE="$directory/minio-secret-key" \
    SG_MINIO_BUCKET_FILE="$directory/minio-bucket" "$@"
}

prepare_staging_resources() {
  create_staging_user
  # Clear only the exact release-derived staging identities. Cleanup is
  # idempotent and cannot match a production database or bucket name.
  "$RELEASE/.venv/bin/python" "$RELEASE/provision_credentials.py" \
    --bindings /mnt/cf_kv_r2/workers/shadowglass-v35/bindings.json \
    --directory "$STAGING_CREDENTIALS" --mode staging-cleanup \
    --staging-database "$STAGING_DATABASE" --staging-bucket "$STAGING_BUCKET" \
    >/dev/null
  "$RELEASE/.venv/bin/python" "$RELEASE/provision_credentials.py" \
    --bindings /mnt/cf_kv_r2/workers/shadowglass-v35/bindings.json \
    --directory "$STAGING_CREDENTIALS" --mode staging-create \
    --staging-database "$STAGING_DATABASE" --staging-bucket "$STAGING_BUCKET" \
    >/dev/null
  STAGING_RESOURCES=1
  sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d "$STAGING_DATABASE" \
    -f - <"$RELEASE/schema.sql" >/dev/null
  sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d "$STAGING_DATABASE" \
    -v role="$STAGING_DATABASE" -f - >/dev/null <<'SQL'
GRANT ALL ON SCHEMA cf_shadowglass_v35 TO :"role";
GRANT ALL ON ALL TABLES IN SCHEMA cf_shadowglass_v35 TO :"role";
GRANT ALL ON ALL SEQUENCES IN SCHEMA cf_shadowglass_v35 TO :"role";
SQL
  credential_env "$STAGING_CREDENTIALS" \
    "$RELEASE/.venv/bin/python" "$RELEASE/verify_endpoints.py" \
    >"$ROOT/staging-endpoint-verification-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/import_d1.py" \
    --dsn-file "$STAGING_CREDENTIALS/database-url" >"$ROOT/staging-d1-import-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/apply_endpoint_overrides.py" \
    --dsn-file "$STAGING_CREDENTIALS/database-url" \
    >"$ROOT/staging-endpoint-overrides-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/import_kv.py" \
    --dsn-file "$STAGING_CREDENTIALS/database-url" \
    --owned-key-sha256 "${OWNED_KV_HASHES[0]}" \
    --owned-key-sha256 "${OWNED_KV_HASHES[1]}" \
    >"$ROOT/staging-kv-import-${RELEASE_ID}.json"
  credential_env "$STAGING_CREDENTIALS" \
    "$RELEASE/.venv/bin/python" "$RELEASE/object_store.py" probe >/dev/null
  chmod 0600 "$ROOT"/staging-*"${RELEASE_ID}.json"
}

provision_data() {
  create_production_users
  "$RELEASE/.venv/bin/python" "$RELEASE/provision_credentials.py" \
    --bindings /mnt/cf_kv_r2/workers/shadowglass-v35/bindings.json
  sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d echo \
    -f - <"$RELEASE/schema.sql" >/dev/null
  consumer_credential_env "$CREDENTIALS" \
    "$RELEASE/.venv/bin/python" "$RELEASE/verify_endpoints.py" \
    >"$ROOT/endpoint-verification-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/import_d1.py" \
    --dsn-file "$CREDENTIALS/migration-database-url" >"$ROOT/d1-import-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/apply_endpoint_overrides.py" \
    --dsn-file "$CREDENTIALS/migration-database-url" \
    >"$ROOT/endpoint-overrides-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/import_kv.py" \
    --dsn-file "$CREDENTIALS/migration-database-url" \
    --owned-key-sha256 "${OWNED_KV_HASHES[0]}" \
    --owned-key-sha256 "${OWNED_KV_HASHES[1]}" >"$ROOT/kv-import-${RELEASE_ID}.json"
  chmod 0600 "$ROOT"/*-"${RELEASE_ID}.json"
  credential_env "$CREDENTIALS" \
    "$RELEASE/.venv/bin/python" "$RELEASE/object_store.py" probe >/dev/null
  sync_release_receipts
}

verify_provisioning_compatibility() {
  "$RELEASE/.venv/bin/python" "$RELEASE/provision_credentials.py" \
    --bindings /mnt/cf_kv_r2/workers/shadowglass-v35/bindings.json \
    >"$ROOT/provision-credentials-recheck-${RELEASE_ID}.json"
  sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d echo \
    -f - <"$RELEASE/schema.sql" >/dev/null
  printf '{"database":"echo","ok":true,"schema":"cf_shadowglass_v35"}\n' \
    >"$ROOT/provision-schema-recheck-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/import_d1.py" \
    --dsn-file "$CREDENTIALS/migration-database-url" \
    >"$ROOT/provision-d1-recheck-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/import_kv.py" \
    --dsn-file "$CREDENTIALS/migration-database-url" \
    --owned-key-sha256 "${OWNED_KV_HASHES[0]}" \
    --owned-key-sha256 "${OWNED_KV_HASHES[1]}" \
    >"$ROOT/provision-kv-recheck-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" "$RELEASE/apply_endpoint_overrides.py" \
    --dsn-file "$CREDENTIALS/migration-database-url" \
    >"$ROOT/provision-endpoint-recheck-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" - "$ROOT" "$RELEASE_ID" <<'PY'
import json, pathlib, sys
root, release = pathlib.Path(sys.argv[1]), sys.argv[2]
paths = {
    "credentials": root / f"provision-credentials-recheck-{release}.json",
    "schema": root / f"provision-schema-recheck-{release}.json",
    "d1": root / f"provision-d1-recheck-{release}.json",
    "kv": root / f"provision-kv-recheck-{release}.json",
    "endpoints": root / f"provision-endpoint-recheck-{release}.json",
}
value = {name: json.loads(path.read_text()) for name, path in paths.items()}
(root / f"provisioning-compatibility-{release}.json").write_text(
    json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
)
PY
  chmod 0600 "$ROOT"/provision-*-"${RELEASE_ID}.json" \
    "$ROOT/provisioning-compatibility-${RELEASE_ID}.json"
}

install_staging() {
  cp "$RELEASE/systemd/$STAGING_UNIT" "/etc/systemd/system/$STAGING_UNIT"
  STAGING_INSTALLED=1
  systemctl daemon-reload
}

wait_health() {
  local base="$1" attempt
  for attempt in {1..45}; do
    if curl --fail --silent --show-error --max-time 2 "$base/health" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

smoke() {
  local base="$1" directory="$2"
  shift 2
  "$RELEASE/.venv/bin/python" "$RELEASE/smoke_live.py" \
    --base "$base" \
    --read-token-file "$directory/api-read-token" \
    --write-token-file "$directory/api-write-token" \
    --smoke-token-file "$directory/api-smoke-token" "$@"
}

run_staging_consumer_canary() {
  local worker_id="staging-${STAGING_SUFFIX}"
  local runtime_path="/opt/shadowglass-v35-staging-consumer"
  systemd-run --quiet --collect --unit="${STAGING_CONSUMER_UNIT%.service}" \
    --service-type=simple --property=User=shadowglass-v35-staging \
    --property=Group=shadowglass-v35-staging --property="WorkingDirectory=$runtime_path" \
    --property="BindReadOnlyPaths=$RELEASE:$runtime_path" \
    --property="InaccessiblePaths=-$runtime_path/src -$runtime_path/evidence -$runtime_path/legacy" \
    --property="LoadCredential=database_url:$STAGING_CREDENTIALS/database-url" \
    --property="LoadCredential=relay_url:$STAGING_CREDENTIALS/relay-url" \
    --property="LoadCredential=relay_allowed_hosts:$STAGING_CREDENTIALS/relay-allowed-hosts" \
    --property="LoadCredential=minio_endpoint:$STAGING_CREDENTIALS/minio-endpoint" \
    --property="LoadCredential=minio_access_key:$STAGING_CREDENTIALS/minio-access-key" \
    --property="LoadCredential=minio_secret_key:$STAGING_CREDENTIALS/minio-secret-key" \
    --property="LoadCredential=minio_bucket:$STAGING_CREDENTIALS/minio-bucket" \
    --property=NoNewPrivileges=yes --property=PrivateTmp=yes \
    --property=PrivateDevices=yes --property=ProtectSystem=strict \
    --property=ProtectHome=tmpfs --property=ProtectControlGroups=yes \
    --property=ProtectKernelTunables=yes --property=ProtectKernelModules=yes \
    --property=ProtectKernelLogs=yes --property=ProtectClock=yes \
    --property=ProtectHostname=yes --property=ProtectProc=invisible \
    --property=ProcSubset=pid --property=LockPersonality=yes \
    --property=MemoryDenyWriteExecute=yes --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes --property=RestrictNamespaces=yes \
    --property=SystemCallArchitectures=native \
    --property="RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" \
    --property=MemoryMax=256M --property=TasksMax=32 \
    --property="Environment=PYTHONDONTWRITEBYTECODE=1" \
    /usr/bin/env "$runtime_path/.venv/bin/python" "$runtime_path/queue_worker.py" --loop \
      --claim-kind acceptance_canary --worker-id "$worker_id" \
      --idle-seconds 0.2 --lease-seconds 60
  for _ in {1..30}; do
    systemctl is-active --quiet "$STAGING_CONSUMER_UNIT" && break
    sleep 0.2
  done
  systemctl is-active --quiet "$STAGING_CONSUMER_UNIT"
  credential_env "$STAGING_CREDENTIALS" \
    "$RELEASE/.venv/bin/python" "$RELEASE/consumer_canary.py" \
      --target-worker-id "$worker_id" --timeout-seconds 90 \
      >"$ROOT/staging-consumer-canary-${RELEASE_ID}.json"
  systemctl stop "$STAGING_CONSUMER_UNIT"
  systemctl reset-failed "$STAGING_CONSUMER_UNIT" >/dev/null 2>&1 || true
  SG_DATABASE_URL_FILE="$STAGING_CREDENTIALS/database-url" \
    "$RELEASE/.venv/bin/python" "$RELEASE/scheduled_job.py" \
      >"$ROOT/staging-scheduler-proof-${RELEASE_ID}.json"
  "$RELEASE/.venv/bin/python" - "$ROOT/staging-scheduler-proof-${RELEASE_ID}.json" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value != {"candidates": 1, "enqueued": 1, "existing": 0, "lock_acquired": True, "probe": False}:
    raise SystemExit("staging scheduler did not enqueue exactly one candidate")
PY
  chmod 0600 "$ROOT/staging-consumer-canary-${RELEASE_ID}.json" \
    "$ROOT/staging-scheduler-proof-${RELEASE_ID}.json"
}

run_staging() {
  prepare_staging_resources
  install_staging
  systemctl start "$STAGING_UNIT"
  wait_health "http://127.0.0.1:8471"
  if [[ "$MODE" == "force-staging-failure" ]]; then
    if smoke "http://127.0.0.1:8471" "$STAGING_CREDENTIALS" --force-fail; then
      echo "forced staging failure unexpectedly passed" >&2
      return 1
    else
      local forced_rc=$?
      [[ $forced_rc -eq 9 ]] || return "$forced_rc"
    fi >"$ROOT/staging-forced-failure-${RELEASE_ID}.json"
    STAGING_FORCED_FAILURE=1
    return 0
  fi
  smoke "http://127.0.0.1:8471" "$STAGING_CREDENTIALS" \
    >"$ROOT/staging-smoke-${RELEASE_ID}.json"
  run_staging_consumer_canary
  systemctl stop "$STAGING_UNIT"
}

install_production_units() {
  local unit
  PROMOTED=1
  systemctl stop "$TIMER_UNIT" "$CONSUMER_UNIT" >/dev/null 2>&1 || true
  for unit in "${UNITS[@]}"; do
    cp "$RELEASE/systemd/$unit" "/etc/systemd/system/$unit"
  done
  atomic_link "$RELEASE" "$CURRENT"
  systemctl daemon-reload
  systemctl enable "$API_UNIT" >/dev/null
  systemctl restart "$API_UNIT"
}

exercise_production_rollback() {
  local unit
  PROMOTED=1
  systemctl stop "${UNITS[@]}" >/dev/null 2>&1 || true
  for unit in "${UNITS[@]}"; do
    cp "$RELEASE/systemd/$unit" "/etc/systemd/system/$unit"
  done
  atomic_link "$RELEASE" "$CURRENT"
  systemctl daemon-reload
  PRODUCTION_FAILURE_INJECTED=1
  if systemctl restart "$API_UNIT" && wait_health "http://127.0.0.1:8470"; then
    if [[ -s "$CREDENTIALS/api-read-token" && -s "$CREDENTIALS/api-write-token" && \
          -s "$CREDENTIALS/api-smoke-token" ]]; then
      if smoke "http://127.0.0.1:8470" "$CREDENTIALS" --force-fail \
        >"$ROOT/production-forced-failure-${RELEASE_ID}.json"; then
        echo "forced production failure unexpectedly passed" >&2
        return 1
      else
        return $?
      fi
    fi
    echo "candidate started without its required production credentials" >&2
    return 1
  fi
  # A first deployment has no production credentials yet, so the candidate
  # unit's fail-closed LoadCredential start is the injected red path.
  return 9
}

run_production_consumer_and_scheduler_proofs() {
  local worker_id="forge-shadowglass-v35-proof"
  systemctl reset-failed "$CONSUMER_PROOF_UNIT" "$SCHEDULED_PROOF_UNIT" \
    >/dev/null 2>&1 || true
  systemctl start "$CONSUMER_PROOF_UNIT"
  systemctl is-active --quiet "$CONSUMER_PROOF_UNIT"
  consumer_credential_env "$CREDENTIALS" \
    "$RELEASE/.venv/bin/python" "$RELEASE/consumer_canary.py" \
      --target-worker-id "$worker_id" --timeout-seconds 90 --require-empty-queue \
      >"$ROOT/consumer-canary-${RELEASE_ID}.json"
  systemctl stop "$CONSUMER_PROOF_UNIT"
  chmod 0600 "$ROOT/consumer-canary-${RELEASE_ID}.json"
  write_receipt "consumer_canary" "passed" "$ROOT/consumer-canary-${RELEASE_ID}.json"
  systemctl start "$SCHEDULED_PROOF_UNIT"
  [[ "$(systemctl show "$SCHEDULED_PROOF_UNIT" --property=Result --value)" == "success" ]]
  [[ "$(systemctl show "$SCHEDULED_PROOF_UNIT" --property=ExecMainStatus --value)" == "0" ]]
  systemctl show "$SCHEDULED_PROOF_UNIT" \
    --property=Id --property=ActiveState --property=Result \
    --property=ExecMainStatus --property=NeedDaemonReload \
    >"$ROOT/scheduler-proof-${RELEASE_ID}.txt"
  chmod 0600 "$ROOT/scheduler-proof-${RELEASE_ID}.txt"
  write_receipt "scheduler_proof" "passed" "$ROOT/scheduler-proof-${RELEASE_ID}.txt"
}

activate_local_triggers() {
  systemctl enable --now "$CONSUMER_UNIT" >/dev/null
  systemctl enable --now "$TIMER_UNIT" >/dev/null
  systemctl is-active --quiet "$CONSUMER_UNIT"
  systemctl is-active --quiet "$TIMER_UNIT"
}

snapshot_production
trap on_error ERR
prepare_release
write_receipt "provenance_verified" "passed" "$RELEASE/.release-source.sha256"

run_staging
cleanup_staging_resources
if [[ "$MODE" == "force-staging-failure" ]]; then
  ((STAGING_FORCED_FAILURE == 1)) || { echo "forced staging gate was not exercised" >&2; exit 1; }
  verify_production_snapshot
  write_receipt "forced_staging_rollback" "rolled_back" "$ROLLBACK_DIR/snapshot-evidence"
  echo '{"ok":true,"gate":"forced_staging_rollback"}'
  exit 0
fi
write_receipt "staging_smoke" "passed" "$ROOT/staging-smoke-${RELEASE_ID}.json"
if [[ "$MODE" == "stage-only" ]]; then
  echo '{"ok":true,"gate":"staging_smoke"}'
  exit 0
fi

require_gate "forced_staging_rollback" "rolled_back"

if [[ "$MODE" == "force-production-failure" ]]; then
  exercise_production_rollback
  echo "forced production failure unexpectedly returned success" >&2
  exit 1
fi

require_gate "forced_production_rollback" "rolled_back"
provision_data
verify_provisioning_compatibility
write_receipt "endpoint_verification" "passed" "$ROOT/endpoint-verification-${RELEASE_ID}.json"
write_receipt "imported_subset_verification" "passed" "$ROOT/provisioning-compatibility-${RELEASE_ID}.json"
write_receipt "provisioning_compatibility" "passed" "$ROOT/provisioning-compatibility-${RELEASE_ID}.json"

install_production_units
wait_health "http://127.0.0.1:8470"
smoke "http://127.0.0.1:8470" "$CREDENTIALS" >"$ROOT/production-smoke-${RELEASE_ID}.json"
chmod 0600 "$ROOT/production-smoke-${RELEASE_ID}.json"
write_receipt "production_smoke" "passed" "$ROOT/production-smoke-${RELEASE_ID}.json"
run_production_consumer_and_scheduler_proofs
sync_release_receipts

if ((SKIP_CLOUDFLARE)); then
  echo '{"ok":true,"gate":"production_smoke","cloudflare_cutover":false}'
  exit 0
fi

"$RELEASE/.venv/bin/python" "$RELEASE/cloudflare_reconcile.py" backup \
  >"$ROOT/cloudflare-backup-${RELEASE_ID}.json"
CF_MUTATED=1
"$RELEASE/.venv/bin/python" "$RELEASE/cloudflare_reconcile.py" disable \
  >"$ROOT/cloudflare-cutover-${RELEASE_ID}.json"
if "$RELEASE/.venv/bin/python" - "$ROOT/cloudflare-cutover-${RELEASE_ID}.json" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value.get("action") == "already_disabled":
    raise SystemExit(0)
if value.get("action") != "disabled":
    raise SystemExit(2)
raise SystemExit(1)
PY
then
  CF_MUTATED=0
else
  cutover_rc=$?
  [[ $cutover_rc -eq 1 ]] || {
    echo "Cloudflare cutover returned an unknown action" >&2
    false
  }
fi
activate_local_triggers
write_receipt "trigger_cutover" "passed" "$ROOT/cloudflare-cutover-${RELEASE_ID}.json"
write_receipt "active_release" "passed" "$RELEASE/.release-source.sha256"
sync_release_receipts
CF_MUTATED=0
trap - ERR
echo '{"ok":true,"gate":"active_release","cloudflare_cutover":true}'
