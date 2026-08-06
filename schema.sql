BEGIN;

CREATE SCHEMA IF NOT EXISTS cf_shadowglass_v7_command;

CREATE TABLE IF NOT EXISTS cf_shadowglass_v7_command.dispatch_receipts (
  id BIGSERIAL PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  target_queue TEXT NOT NULL CHECK (target_queue IN ('publicsearch','texasfile','tyler')),
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 80),
  payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  state TEXT NOT NULL CHECK (state IN ('dispatching','dispatched','failed')),
  error_class TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  dispatched_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS dispatch_receipts_state_idx
  ON cf_shadowglass_v7_command.dispatch_receipts (state, updated_at);

CREATE TABLE IF NOT EXISTS cf_shadowglass_v7_command.rate_windows (
  subject_sha256 TEXT NOT NULL CHECK (subject_sha256 ~ '^[0-9a-f]{64}$'),
  action TEXT NOT NULL,
  window_started_at TIMESTAMPTZ NOT NULL,
  request_count INTEGER NOT NULL CHECK (request_count > 0),
  PRIMARY KEY (subject_sha256, action, window_started_at)
);

CREATE TABLE IF NOT EXISTS cf_shadowglass_v7_command.schedules (
  id BIGSERIAL PRIMARY KEY,
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 80),
  target_queue TEXT NOT NULL CHECK (target_queue IN ('publicsearch','texasfile','tyler')),
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  idempotency_prefix TEXT NOT NULL UNIQUE,
  interval_seconds INTEGER NOT NULL CHECK (interval_seconds BETWEEN 60 AND 86400),
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  next_run_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  last_run_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- No schedule is enabled by migration. Enabling work is a separate explicit action.

COMMIT;

