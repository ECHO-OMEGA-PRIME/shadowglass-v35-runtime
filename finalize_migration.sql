\if :{?active_release}
\else
\echo 'active_release psql variable is required'
\quit
\endif
\if :{?source_tree}
\else
\echo 'source_tree psql variable is required'
\quit
\endif
\if :{?source_digest}
\else
\echo 'source_digest psql variable is required'
\quit
\endif

BEGIN;
SELECT set_config('echo.shadowglass_v35.active_release', :'active_release', true);
SELECT set_config('echo.shadowglass_v35.source_tree', :'source_tree', true);
SELECT set_config('echo.shadowglass_v35.source_digest', :'source_digest', true);

DO $finalize$
DECLARE
    catalog_rows integer;
    active_release constant text := current_setting('echo.shadowglass_v35.active_release');
    release_tree constant text := current_setting('echo.shadowglass_v35.source_tree');
    release_digest constant text := current_setting('echo.shadowglass_v35.source_digest');
    catalog_sha constant text := 'd895330aa745f042a077aeebb5e3e3611305553d64942ada0ef3fac18de447fd';
    d1_sha constant text := '72926ce6bf1605d577f5e38c43e2ef4376021b63422dfedc0c5a11b3ab53f200';
    kv_sha constant text := '5722a985d51eba21b56be703fded5954fafee6f6d552960ebe9ae3d6cb962731';
    endpoints_sha constant text := '64adbf406dd30bf1723dc9cfbd35fc6cc0c24d143ae8b01ca323eccdbb717d00';
    expected_counts constant jsonb := '{"counties":102,"deed_records":212600,"instrument_types":0,"r2_uploads":0,"scrape_jobs":0,"scrape_logs":0}'::jsonb;
BEGIN
    IF active_release !~ '^/home/forge/shadowglass-v35/releases/[0-9a-f]{40}$'
       OR release_tree !~ '^[0-9a-f]{40}$'
       OR release_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: invalid active release path';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM inventory.cf_migration_status
         WHERE lower(worker_name) = 'shadowglass-v35'
           AND status = 'migrated'
           AND btrim(source_sha256) = catalog_sha
           AND source_route_count = 17
           AND target_route_count = 17
           AND matched_route_count = 17
           AND route_coverage = 1.0
           AND forge_service_dir = 'shadowglass-v35'
           AND forge_unit = 'shadowglass-v35.service'
           AND health_state = 'healthy'
    ) THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: canonical audit is not 17/17/17 healthy';
    END IF;
    IF (
        SELECT coalesce(jsonb_object_agg(source_identity, source_count ORDER BY source_identity), '{}'::jsonb)
          FROM cf_shadowglass_v35.migration_receipts
         WHERE source_kind = 'd1_table'
           AND source_sha256 = d1_sha
           AND source_count = target_count
           AND source_digest = target_digest
    ) <> expected_counts THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: exact D1 reconciliation is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM cf_shadowglass_v35.migration_receipts
         WHERE source_kind = 'kv_namespace'
           AND source_identity = 'shadowglass-v35'
           AND source_sha256 = kv_sha
           AND source_count = 2 AND target_count = 2
           AND source_digest = target_digest
    ) THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: scoped KV reconciliation is missing';
    END IF;
    IF (
        SELECT count(*)
          FROM cf_shadowglass_v35.migration_receipts
         WHERE source_kind = 'd1_imported_subset_v1'
           AND source_sha256 = d1_sha
           AND source_count = target_count
           AND source_digest = target_digest
           AND details @> '{"version":1}'::jsonb
    ) <> 6 OR NOT EXISTS (
        SELECT 1
          FROM cf_shadowglass_v35.migration_receipts
         WHERE source_kind = 'kv_imported_subset_v1'
           AND source_identity = 'shadowglass-v35'
           AND source_sha256 = kv_sha
           AND source_count = 2 AND target_count = 2
           AND source_digest = target_digest
           AND details @> '{"identity":"scope+key+value","version":1}'::jsonb
    ) THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: rescued imported-subset proof is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM cf_shadowglass_v35.migration_receipts
         WHERE source_kind = 'endpoint-overrides'
           AND source_identity = 'county-endpoints-v1:' || endpoints_sha
           AND source_sha256 = endpoints_sha
           AND source_count = 18 AND target_count = 102
           AND source_digest = target_digest
           AND details @> '{"active_count":7,"inactive_count":11}'::jsonb
    ) OR (
        SELECT count(*) FROM cf_shadowglass_v35.counties
         WHERE is_active = 1
    ) <> 7 THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: reviewed endpoint activation is missing';
    END IF;
    IF NOT (
        SELECT coalesce(
                   bool_and(receipt.status IS NOT NULL AND receipt.status = expected_status),
                   false
               )
          FROM (
            VALUES
              ('provenance_verified', 'passed'),
              ('forced_staging_rollback', 'rolled_back'),
              ('staging_smoke', 'passed'),
              ('forced_production_rollback', 'rolled_back'),
              ('endpoint_verification', 'passed'),
              ('imported_subset_verification', 'passed'),
              ('provisioning_compatibility', 'passed'),
              ('production_smoke', 'passed'),
              ('consumer_canary', 'passed'),
              ('scheduler_proof', 'passed'),
              ('trigger_cutover', 'passed'),
              ('active_release', 'passed'),
              ('fresh_attestation', 'passed')
          ) AS required(gate, expected_status)
          LEFT JOIN LATERAL (
            SELECT event.status
              FROM cf_shadowglass_v35.deployment_events event
             WHERE event.gate = required.gate
               AND event.release_id = regexp_replace(active_release, '^.*/', '')
               AND event.source_tree = release_tree
               AND event.source_digest = release_digest
             ORDER BY event.occurred_at DESC, event.id DESC
             LIMIT 1
          ) receipt ON true
    ) THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: deployment/rollback gate chain is incomplete';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM cf_shadowglass_v35.deployment_events
         WHERE gate = 'fresh_attestation'
           AND release_id = regexp_replace(active_release, '^.*/', '')
           AND source_tree = release_tree
           AND source_digest = release_digest
           AND status = 'passed'
           AND occurred_at >= now() - interval '5 minutes'
    ) THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: active attestation is stale';
    END IF;
    IF (
        SELECT count(*)
          FROM cf_shadowglass_v35.migration_receipts
         WHERE source_kind = 'd1_imported_subset_v1'
           AND completed_at >= now() - interval '5 minutes'
    ) <> 6 OR NOT EXISTS (
        SELECT 1
          FROM cf_shadowglass_v35.migration_receipts
         WHERE source_kind = 'kv_imported_subset_v1'
           AND source_count = 2 AND target_count = 2
           AND completed_at >= now() - interval '5 minutes'
    ) OR NOT EXISTS (
        SELECT 1
          FROM cf_shadowglass_v35.migration_receipts
         WHERE source_kind = 'endpoint-overrides'
           AND source_count = 18 AND target_count = 102
           AND completed_at >= now() - interval '5 minutes'
    ) THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: imported subset evidence is stale';
    END IF;
    IF NOT EXISTS (
        WITH gate_order AS (
            SELECT
              max(occurred_at) FILTER (WHERE gate = 'forced_staging_rollback') AS forced_staging,
              max(occurred_at) FILTER (WHERE gate = 'forced_production_rollback') AS forced_production,
              max(occurred_at) FILTER (WHERE gate = 'staging_smoke') AS staging_smoke,
              max(occurred_at) FILTER (WHERE gate = 'provisioning_compatibility') AS provisioning_compatibility,
              max(occurred_at) FILTER (WHERE gate = 'production_smoke') AS production_smoke,
              max(occurred_at) FILTER (WHERE gate = 'consumer_canary') AS consumer_canary,
              max(occurred_at) FILTER (WHERE gate = 'scheduler_proof') AS scheduler_proof,
              max(occurred_at) FILTER (WHERE gate = 'trigger_cutover') AS trigger_cutover,
              max(occurred_at) FILTER (WHERE gate = 'active_release') AS active_release_event,
              max(occurred_at) FILTER (WHERE gate = 'fresh_attestation') AS fresh_attestation
            FROM cf_shadowglass_v35.deployment_events
            WHERE release_id = regexp_replace(active_release, '^.*/', '')
              AND source_tree = release_tree
              AND source_digest = release_digest
        )
        SELECT 1 FROM gate_order
         WHERE forced_staging < forced_production
           AND forced_production < staging_smoke
           AND staging_smoke < provisioning_compatibility
           AND provisioning_compatibility < production_smoke
           AND production_smoke < consumer_canary
           AND consumer_canary < scheduler_proof
           AND scheduler_proof < trigger_cutover
           AND trigger_cutover < active_release_event
           AND active_release_event < fresh_attestation
    ) THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: gate events are not ordered';
    END IF;

    UPDATE arcanum_sdk.cf_artifact_catalog
       SET status = 'verified',
           target_origin = 'http://127.0.0.1:8470',
           notes = 'Verified FORGE replacement: independent provenance, 17/17 route contract, exact D1/scoped KV reconciliation, reviewed live county endpoints, staging/production/rollback gates, and reversible Queue/cron/workers.dev cutover.',
           metadata = coalesce(metadata, '{}'::jsonb) || jsonb_build_object(
               'forge_service_dir', '/home/forge/shadowglass-v35',
               'forge_unit', 'shadowglass-v35.service',
               'consumer_unit', 'shadowglass-v35-consumer.service',
               'timer_unit', 'shadowglass-v35-scheduled.timer',
               'migration_contract', '/home/forge/shadowglass-v35/current/migration_contract.json',
               'active_release', active_release,
               'catalog_rescued_sha256', catalog_sha,
               'route_contract', '17/17',
               'r2_archive_state', 'no-referenced-rescued-rows-new-writes-minio',
               'active_counties', 7,
               'verified_at', now()
           ),
           updated_at = now()
     WHERE kind = 'worker' AND lower(name) = 'shadowglass-v35';
    GET DIAGNOSTICS catalog_rows = ROW_COUNT;
    IF catalog_rows <> 1 THEN
        RAISE EXCEPTION 'ShadowGlass v35 finalization refused: expected one catalog row, updated %', catalog_rows;
    END IF;
END
$finalize$;

INSERT INTO arcanum_sdk.cf_migration_track
    (cf_service_name, cf_service_kind, status, priority, echo_replacement_kind,
     echo_target_path, owner_agent, notes, migrated_at, updated_at)
VALUES
    ('shadowglass-v35', 'worker', 'migrated', 6, 'fastapi',
     '/home/forge/shadowglass-v35', 'continuous-builder',
     'Independent provenance, 17/17 route contract, exact D1/scoped-KV/endpoint receipts, seven reviewed live county endpoints, live smoke, rollback proof, and reversible trigger cutover are green; absent historical R2 bytes remain an explicit non-serving delta.',
     now(), now())
ON CONFLICT (cf_service_name) DO UPDATE SET
    status = EXCLUDED.status,
    priority = EXCLUDED.priority,
    echo_replacement_kind = EXCLUDED.echo_replacement_kind,
    echo_target_path = EXCLUDED.echo_target_path,
    owner_agent = EXCLUDED.owner_agent,
    notes = EXCLUDED.notes,
    migrated_at = EXCLUDED.migrated_at,
    updated_at = EXCLUDED.updated_at;

COMMIT;
