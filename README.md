# ShadowGlass v7 Command Runtime

Private FORGE replacement for the recovered `shadowglass-v7-command` Cloudflare Worker. It preserves the exact 17-route fetch surface and the scheduled-handler boundary while moving command state to PostgreSQL and retaining the three existing Cloudflare Queues as the delivery plane for PublicSearch, TexasFile, and Tyler consumers.

## Safety properties

- Every mutating request requires a constant-time bearer or `X-Echo-Command-Key` check.
- Dispatches require an `Idempotency-Key`; ambiguous provider results fail closed instead of replaying work.
- A PostgreSQL rate window bounds authenticated writes to 60 requests per route per minute.
- Queue target names are an enum and provider identifiers are validated before transport.
- Caller-selected source URLs and unknown JSON fields are rejected.
- Batch fan-out is capped at 100 items and queue messages at 128 KB.
- The scheduler reads only explicitly enabled rows; migration enables no schedule by default.
- Structured logs contain request IDs, paths, status, and duration, but no request bodies or credentials.
- Runtime secrets live as root-owned mode `0400` files under `/etc/echo/credentials/shadowglass-v7-command` and reach the unprivileged process only through systemd's per-unit credential broker.

## Data plane

The recovered Command, PublicSearch, and Tyler Workers shared the same D1, KV, and R2 identities. Their imported tables therefore remain canonical in `cf_shadowglass_v7_tyler`. Command-only dispatch receipts, schedules, and rate windows are isolated in `cf_shadowglass_v7_command`.

The original catalog hash and the strict recovered-bundle hash are deliberately recorded separately in `migration_contract.json`; they are provenance layers, not asserted equivalents.

## Local verification

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q tests
python -m ruff check .
python -m py_compile app.py storage.py provider_queue.py scheduler.py smoke_live.py ops/provision.py
```

The tests prove exact route parity, authenticated mutations, exact CORS behavior, idempotent provider dispatch, bounded fan-out, rate-limit denial, sensitive-read authentication, security headers, provider target isolation, and an idle-by-default scheduler.

## FORGE release

The production path is `/home/forge/shadowglass-v7-command`, with immutable releases under `releases/<git-sha>` and an atomic `current` symlink. `ops/provision.py` discovers the three exact queue identities using existing root-only provider credentials, creates a least-privilege database role, and emits metadata-only success output.

Install the API and timer units from `ops/`, apply `schema.sql` as the PostgreSQL administrator, and provision credentials before the first boot. The API binds only to the verified-free loopback port `127.0.0.1:8287`; ingress is intentionally separate from this migration.

Deployment is accepted only after:

1. the candidate boots on a staging port against an isolated command schema;
2. all 17 route behaviors pass, including auth, validation, and CORS negatives;
3. a production canary reaches one real provider queue and is consumed/cleaned at the downstream boundary;
4. timer execution is green with zero enabled schedules;
5. rollback restores the previous release and the candidate can be re-promoted;
6. the authoritative Cloudflare migration auditor reports `migrated` and `healthy`.

## Operations

- Health: `GET http://127.0.0.1:8287/health`
- API unit: `shadowglass-v7-command.service`
- Scheduler unit/timer: `shadowglass-v7-command-scheduler.service` / `.timer`
- Provider or database failure: HTTP `503`, no automatic replay of an unresolved dispatch
- Rollback: atomically repoint `current` to the preceding immutable release, restart the API, and re-run health

No rescued source, D1 row data, queue payloads, or credentials are stored in this repository.
