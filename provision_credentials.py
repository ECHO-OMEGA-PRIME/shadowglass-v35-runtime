#!/usr/bin/env python3
"""Provision isolated runtime credentials without disclosing their values."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable


ROLE = "cf_shadowglass_v35"
MIGRATOR_ROLE = "cf_shadowglass_v35_migrator"
CONSUMER_ROLE = "cf_shadowglass_v35_consumer"
SCHEDULER_ROLE = "cf_shadowglass_v35_scheduler"
DATABASE = "echo"
DEFAULT_DIRECTORY = Path("/etc/echo/credentials/shadowglass-v35")
STAGING_DIRECTORY = Path("/etc/echo/credentials/shadowglass-v35-staging")
CLOUDFLARE_ACCOUNT_SERVICE = "harvested.cloudflare.0000"
CLOUDFLARE_ACCOUNT_USERNAME = "account_id"
MINIO_ADMIN_SERVICE = "harvested.minio.0000"
MINIO_ADMIN_USERNAME = "echo-admin"
SDK_URL = os.getenv("ECHO_SDK_URL", "http://127.0.0.1:8000/sdk/invoke")
KEY_FILE = Path(os.getenv("ECHO_SOVEREIGN_KEY_FILE", "/home/forge/.echo_sovereign_key"))
MINIO_ENDPOINT_CONFIG = Path(
    "/etc/systemd/system/echo-county-records.service.d/minio.conf"
)
MINIO_CREDENTIAL_CONFIG = Path(
    "/etc/systemd/system/echo-county-records.service.d/minio-creds.conf"
)
LOCAL_RELAY_ORIGIN = "http://127.0.0.1:8088"
LOCAL_RELAY_HOST = "127.0.0.1"
OUTPUT_BUCKET = "shadowglass-v35"


def _binding_records(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("name") == "RELAY_URL":
            yield value
        for nested in value.values():
            yield from _binding_records(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _binding_records(nested)


def _relay_origin(bindings_path: Path) -> tuple[str, str]:
    document = json.loads(bindings_path.read_text(encoding="utf-8"))
    records = list(_binding_records(document))
    if len(records) != 1:
        raise RuntimeError("expected exactly one RELAY_URL binding")
    record = records[0]
    raw = next(
        (
            str(record[name]).strip()
            for name in ("text", "value", "plain_text")
            if isinstance(record.get(name), str) and str(record[name]).strip()
        ),
        "",
    )
    parsed = urllib.parse.urlsplit(raw)
    host = (parsed.hostname or "").casefold()
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("RELAY_URL is not an exact http(s) origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("RELAY_URL port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise RuntimeError("RELAY_URL port is invalid")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")), host


def _read_or_create(path: Path, factory: Any) -> str:
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            raise RuntimeError(f"existing credential is empty: {path.name}")
        return value
    value = str(factory())
    _atomic_write(path, value)
    return value


def _systemd_environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("Environment="):
            continue
        assignment = line.split("=", 1)[1].strip().strip('"')
        name, separator, value = assignment.partition("=")
        if separator and name:
            values[name] = value
    return values


def _sovereign_key() -> str:
    match = re.search(
        r"SOVEREIGN_KEY\s*=\s*(\S+)",
        KEY_FILE.read_text(encoding="utf-8"),
    )
    if not match:
        raise RuntimeError("SDK credential unavailable")
    return match.group(1)


def _vault_secret(service: str, username: str, *, purpose: str) -> str:
    payload = {
        "envelope_version": 1,
        "capability": "echo.vault.get",
        "params": {
            "command": "get",
            "service": service,
            "username": username,
        },
        "context": {"bypass_reason": purpose},
    }
    request = urllib.request.Request(
        SDK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Echo-API-Key": _sovereign_key(),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.loads(response.read())
    secret = ((result.get("result") or {}).get("body") or {}).get("secret")
    if not secret:
        raise RuntimeError("Vault credential unavailable")
    return str(secret).strip()


def _minio_configuration() -> tuple[str, str, str]:
    public = _systemd_environment(MINIO_ENDPOINT_CONFIG)
    private = _systemd_environment(MINIO_CREDENTIAL_CONFIG)
    endpoint = public.get("MINIO_ENDPOINT", "").strip()
    access = (
        private.get("ECHO_MINIO_ACCESS_KEY")
        or private.get("MINIO_ACCESS_KEY")
        or ""
    ).strip()
    secret = (
        private.get("ECHO_MINIO_SECRET_KEY")
        or private.get("MINIO_SECRET_KEY")
        or ""
    ).strip()
    if not access and not secret:
        access = MINIO_ADMIN_USERNAME
        secret = _vault_secret(
            MINIO_ADMIN_SERVICE,
            MINIO_ADMIN_USERNAME,
            purpose=(
                "Provision an isolated ShadowGlass v35 MinIO bucket and scoped service "
                "identity during the verified reversible FORGE deployment gate."
            ),
        )
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not access
        or not secret
    ):
        raise RuntimeError("canonical MinIO configuration is invalid")
    return endpoint.rstrip("/"), access, secret


def _atomic_write(path: Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, stat.S_IRUSR)
    finally:
        if temporary.exists():
            temporary.unlink()


def _provision_role(role: str, password: str, connection_limit: int) -> None:
    if role not in {ROLE, MIGRATOR_ROLE, CONSUMER_ROLE, SCHEDULER_ROLE}:
        raise ValueError("role is not allowlisted")
    escaped = password.replace("'", "''")
    sql = f"""
DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
    CREATE ROLE {role} LOGIN PASSWORD '{escaped}' NOSUPERUSER NOCREATEDB
      NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT {connection_limit};
  ELSE
    ALTER ROLE {role} WITH LOGIN PASSWORD '{escaped}' NOSUPERUSER NOCREATEDB
      NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT {connection_limit};
  END IF;
END
$role$;
ALTER ROLE {role} SET search_path = cf_shadowglass_v35, pg_catalog;
"""
    subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", DATABASE, "-f", "-"],
        input=sql,
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def _mc_environment(endpoint: str, access: str, secret: str) -> dict[str, str]:
    environment = dict(os.environ)
    quoted_access = urllib.parse.quote(access, safe="")
    quoted_secret = urllib.parse.quote(secret, safe="")
    parsed = urllib.parse.urlsplit(endpoint)
    environment["MC_HOST_sgv35admin"] = urllib.parse.urlunsplit(
        (parsed.scheme, f"{quoted_access}:{quoted_secret}@{parsed.netloc}", "", "", "")
    )
    return environment


def _run_mc(arguments: list[str], *, endpoint: str, access: str, secret: str) -> None:
    subprocess.run(
        ["mc", "--quiet", *arguments],
        env=_mc_environment(endpoint, access, secret),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _provision_minio_consumer(
    directory: Path, *, endpoint: str, admin_access: str, admin_secret: str
) -> None:
    access = _read_or_create(
        directory / "minio-access-key", lambda: f"sgv35-{secrets.token_hex(12)}"
    )
    secret = _read_or_create(
        directory / "minio-secret-key", lambda: secrets.token_urlsafe(48)
    )
    policy_name = "shadowglass-v35-consumer"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{OUTPUT_BUCKET}"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{OUTPUT_BUCKET}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:DeleteObject"],
                "Resource": [
                    f"arn:aws:s3:::{OUTPUT_BUCKET}/_acceptance_canary/v1/*"
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::shadowglass/*"],
            },
        ],
    }
    _run_mc(
        ["mb", "--ignore-existing", f"sgv35admin/{OUTPUT_BUCKET}"],
        endpoint=endpoint,
        access=admin_access,
        secret=admin_secret,
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        json.dump(policy, handle, separators=(",", ":"), sort_keys=True)
        policy_path = Path(handle.name)
    try:
        os.chmod(policy_path, stat.S_IRUSR)
        _run_mc(
            ["admin", "policy", "create", "sgv35admin", policy_name, str(policy_path)],
            endpoint=endpoint,
            access=admin_access,
            secret=admin_secret,
        )
        _run_mc(
            ["admin", "user", "add", "sgv35admin", access, secret],
            endpoint=endpoint,
            access=admin_access,
            secret=admin_secret,
        )
        _run_mc(
            ["admin", "policy", "attach", "sgv35admin", policy_name, "--user", access],
            endpoint=endpoint,
            access=admin_access,
            secret=admin_secret,
        )
    finally:
        if policy_path.exists():
            os.chmod(policy_path, stat.S_IRUSR | stat.S_IWUSR)
        policy_path.unlink(missing_ok=True)
    _atomic_write(directory / "minio-endpoint", endpoint)
    _atomic_write(directory / "minio-bucket", OUTPUT_BUCKET)


def _validated_staging_identity(database: str, bucket: str) -> None:
    import re

    if not re.fullmatch(r"sgv35_stage_[0-9a-f]{12}", database):
        raise ValueError("staging database identity is invalid")
    if not re.fullmatch(r"shadowglass-v35-stage-[0-9a-f]{12}", bucket):
        raise ValueError("staging bucket identity is invalid")


def _provision_staging_minio(
    directory: Path,
    *,
    bucket: str,
    endpoint: str,
    admin_access: str,
    admin_secret: str,
) -> None:
    suffix = bucket.rsplit("-", 1)[-1]
    access = f"sgv35-stage-{suffix}"
    secret = secrets.token_urlsafe(48)
    policy_name = f"sgv35-stage-{suffix}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:DeleteObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/_acceptance_canary/v1/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::shadowglass/*"],
            },
        ],
    }
    _run_mc(
        ["mb", "sgv35admin/" + bucket],
        endpoint=endpoint,
        access=admin_access,
        secret=admin_secret,
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        json.dump(policy, handle, separators=(",", ":"), sort_keys=True)
        policy_path = Path(handle.name)
    try:
        os.chmod(policy_path, stat.S_IRUSR)
        _run_mc(
            ["admin", "policy", "create", "sgv35admin", policy_name, str(policy_path)],
            endpoint=endpoint,
            access=admin_access,
            secret=admin_secret,
        )
        _run_mc(
            ["admin", "user", "add", "sgv35admin", access, secret],
            endpoint=endpoint,
            access=admin_access,
            secret=admin_secret,
        )
        _run_mc(
            ["admin", "policy", "attach", "sgv35admin", policy_name, "--user", access],
            endpoint=endpoint,
            access=admin_access,
            secret=admin_secret,
        )
    finally:
        if policy_path.exists():
            os.chmod(policy_path, stat.S_IRUSR | stat.S_IWUSR)
        policy_path.unlink(missing_ok=True)
    _atomic_write(directory / "minio-endpoint", endpoint)
    _atomic_write(directory / "minio-access-key", access)
    _atomic_write(directory / "minio-secret-key", secret)
    _atomic_write(directory / "minio-bucket", bucket)


def _staging_create(
    directory: Path,
    *,
    database: str,
    bucket: str,
    minio_endpoint: str,
    minio_access: str,
    minio_secret: str,
) -> None:
    _validated_staging_identity(database, bucket)
    if directory != STAGING_DIRECTORY:
        raise ValueError("staging credential directory is not allowlisted")
    if directory.exists():
        raise RuntimeError("staging credential directory already exists")
    directory.mkdir(parents=True, mode=stat.S_IRWXU)
    password = secrets.token_urlsafe(36)
    escaped = password.replace("'", "''")
    sql = f"""
CREATE ROLE {database} LOGIN PASSWORD '{escaped}' NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT 4;
CREATE DATABASE {database} OWNER {database};
"""
    try:
        subprocess.run(
            ["sudo", "-u", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-f", "-"],
            input=sql,
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        encoded = urllib.parse.quote(password, safe="")
        _atomic_write(
            directory / "database-url",
            f"postgresql://{database}:{encoded}@127.0.0.1:5432/{database}",
        )
        for name in ("api-read-token", "api-write-token", "api-smoke-token"):
            _atomic_write(directory / name, secrets.token_urlsafe(48))
        _atomic_write(directory / "relay-url", LOCAL_RELAY_ORIGIN)
        _atomic_write(directory / "relay-allowed-hosts", LOCAL_RELAY_HOST)
        _provision_staging_minio(
            directory,
            bucket=bucket,
            endpoint=minio_endpoint,
            admin_access=minio_access,
            admin_secret=minio_secret,
        )
    except Exception:
        _staging_cleanup(
            directory,
            database=database,
            bucket=bucket,
            minio_endpoint=minio_endpoint,
            minio_access=minio_access,
            minio_secret=minio_secret,
        )
        raise


def _staging_cleanup(
    directory: Path,
    *,
    database: str,
    bucket: str,
    minio_endpoint: str,
    minio_access: str,
    minio_secret: str,
) -> None:
    _validated_staging_identity(database, bucket)
    if directory != STAGING_DIRECTORY:
        raise ValueError("staging credential directory is not allowlisted")
    suffix = bucket.rsplit("-", 1)[-1]
    policy_name = f"sgv35-stage-{suffix}"
    runtime_access = f"sgv35-stage-{suffix}"
    # Cleanup is deliberately idempotent so a failed partial create cannot
    # strand database state or credentials merely because its bucket is absent.
    commands = []
    commands.append(["admin", "user", "remove", "sgv35admin", runtime_access])
    commands.extend(
        (
            ["admin", "policy", "remove", "sgv35admin", policy_name],
            ["rm", "--recursive", "--force", "sgv35admin/" + bucket],
            ["rb", "--force", "sgv35admin/" + bucket],
        )
    )
    for command in commands:
        subprocess.run(
            ["mc", "--quiet", *command],
            env=_mc_environment(minio_endpoint, minio_access, minio_secret),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    bucket_probe = subprocess.run(
        ["mc", "--quiet", "stat", "sgv35admin/" + bucket],
        env=_mc_environment(minio_endpoint, minio_access, minio_secret),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if bucket_probe.returncode == 0:
        raise RuntimeError("staging bucket cleanup did not converge")
    user_probe = subprocess.run(
        ["mc", "--quiet", "admin", "user", "info", "sgv35admin", runtime_access],
        env=_mc_environment(minio_endpoint, minio_access, minio_secret),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    policy_probe = subprocess.run(
        ["mc", "--quiet", "admin", "policy", "info", "sgv35admin", policy_name],
        env=_mc_environment(minio_endpoint, minio_access, minio_secret),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if user_probe.returncode == 0 or policy_probe.returncode == 0:
        raise RuntimeError("staging MinIO identity cleanup did not converge")
    subprocess.run(
        ["sudo", "-u", "postgres", "dropdb", "--if-exists", database],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["sudo", "-u", "postgres", "dropuser", "--if-exists", database],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    database_probe = subprocess.run(
        [
            "sudo",
            "-u",
            "postgres",
            "psql",
            "-XAt",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            (
                "SELECT count(*) FROM pg_database WHERE datname = "
                f"'{database}'"
            ),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    role_probe = subprocess.run(
        [
            "sudo",
            "-u",
            "postgres",
            "psql",
            "-XAt",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            f"SELECT count(*) FROM pg_roles WHERE rolname = '{database}'",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    if database_probe.stdout.strip() != "0" or role_probe.stdout.strip() != "0":
        raise RuntimeError("staging PostgreSQL cleanup did not converge")
    if directory.exists():
        shutil.rmtree(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--directory", type=Path, default=DEFAULT_DIRECTORY)
    parser.add_argument(
        "--mode", choices=("production", "staging-create", "staging-cleanup"), default="production"
    )
    parser.add_argument("--staging-database", default="")
    parser.add_argument("--staging-bucket", default="")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    minio_endpoint, minio_access, minio_secret = _minio_configuration()
    if args.check_only:
        legacy_relay_origin, legacy_relay_host = _relay_origin(args.bindings)
        print(
            json.dumps(
                {
                    "ok": True,
                    "legacy_relay_provenance_valid": bool(
                        legacy_relay_origin and legacy_relay_host
                    ),
                    "local_relay_origin": LOCAL_RELAY_ORIGIN,
                    "object_store_configured": bool(
                        minio_endpoint and minio_access and minio_secret
                    ),
                }
            )
        )
        return 0
    if os.geteuid() != 0:
        raise SystemExit("credential provisioning requires root")
    if args.mode == "staging-create":
        _staging_create(
            args.directory,
            database=args.staging_database,
            bucket=args.staging_bucket,
            minio_endpoint=minio_endpoint,
            minio_access=minio_access,
            minio_secret=minio_secret,
        )
        print(json.dumps({"ok": True, "mode": args.mode}, sort_keys=True))
        return 0
    if args.mode == "staging-cleanup":
        _staging_cleanup(
            args.directory,
            database=args.staging_database,
            bucket=args.staging_bucket,
            minio_endpoint=minio_endpoint,
            minio_access=minio_access,
            minio_secret=minio_secret,
        )
        print(json.dumps({"ok": True, "mode": args.mode}, sort_keys=True))
        return 0
    legacy_relay_origin, legacy_relay_host = _relay_origin(args.bindings)
    args.directory.mkdir(parents=True, exist_ok=True)
    os.chmod(args.directory, stat.S_IRWXU)

    read_token = _read_or_create(args.directory / "api-read-token", lambda: secrets.token_urlsafe(48))
    write_token = _read_or_create(args.directory / "api-write-token", lambda: secrets.token_urlsafe(48))
    smoke_token = _read_or_create(
        args.directory / "api-smoke-token", lambda: secrets.token_urlsafe(48)
    )
    password = _read_or_create(args.directory / "database-password", lambda: secrets.token_urlsafe(36))
    migrator_password = _read_or_create(
        args.directory / "migration-database-password", lambda: secrets.token_urlsafe(36)
    )
    consumer_password = _read_or_create(
        args.directory / "consumer-database-password", lambda: secrets.token_urlsafe(36)
    )
    scheduler_password = _read_or_create(
        args.directory / "scheduler-database-password", lambda: secrets.token_urlsafe(36)
    )
    _provision_role(ROLE, password, 16)
    _provision_role(MIGRATOR_ROLE, migrator_password, 2)
    _provision_role(CONSUMER_ROLE, consumer_password, 4)
    _provision_role(SCHEDULER_ROLE, scheduler_password, 2)
    encoded_password = urllib.parse.quote(password, safe="")
    dsn = f"postgresql://{ROLE}:{encoded_password}@127.0.0.1:5432/{DATABASE}"
    encoded_migrator_password = urllib.parse.quote(migrator_password, safe="")
    migrator_dsn = (
        f"postgresql://{MIGRATOR_ROLE}:{encoded_migrator_password}"
        f"@127.0.0.1:5432/{DATABASE}"
    )
    encoded_consumer_password = urllib.parse.quote(consumer_password, safe="")
    consumer_dsn = (
        f"postgresql://{CONSUMER_ROLE}:{encoded_consumer_password}"
        f"@127.0.0.1:5432/{DATABASE}"
    )
    encoded_scheduler_password = urllib.parse.quote(scheduler_password, safe="")
    scheduler_dsn = (
        f"postgresql://{SCHEDULER_ROLE}:{encoded_scheduler_password}"
        f"@127.0.0.1:5432/{DATABASE}"
    )
    _atomic_write(args.directory / "database-url", dsn)
    _atomic_write(args.directory / "migration-database-url", migrator_dsn)
    _atomic_write(args.directory / "consumer-database-url", consumer_dsn)
    _atomic_write(args.directory / "scheduler-database-url", scheduler_dsn)
    _atomic_write(args.directory / "relay-url", LOCAL_RELAY_ORIGIN)
    _atomic_write(args.directory / "relay-allowed-hosts", LOCAL_RELAY_HOST)
    cloudflare_account_id = _vault_secret(
        CLOUDFLARE_ACCOUNT_SERVICE,
        CLOUDFLARE_ACCOUNT_USERNAME,
        purpose=(
            "Bind the reversible ShadowGlass v35 provider reconciliation to the "
            "authorized new Cloudflare account without embedding provider identity."
        ),
    )
    if not re.fullmatch(r"[0-9a-f]{32}", cloudflare_account_id):
        raise RuntimeError("Cloudflare account identity is invalid")
    _atomic_write(args.directory / "cloudflare-account-id", cloudflare_account_id)
    _provision_minio_consumer(
        args.directory,
        endpoint=minio_endpoint,
        admin_access=minio_access,
        admin_secret=minio_secret,
    )
    if any(
        hmac_compare(left, right)
        for left, right in (
            (read_token, write_token),
            (read_token, smoke_token),
            (write_token, smoke_token),
        )
    ):
        raise RuntimeError("read and write credentials unexpectedly match")
    print(
        json.dumps(
            {
                "ok": True,
                "directory_mode": "0700",
                "credential_mode": "0400",
                "database_role": ROLE,
                "migration_role": MIGRATOR_ROLE,
                "consumer_role": CONSUMER_ROLE,
                "scheduler_role": SCHEDULER_ROLE,
                "minio_identity": "bucket-scoped-consumer",
                "relay_configured": True,
            },
            sort_keys=True,
        )
    )
    return 0


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


if __name__ == "__main__":
    raise SystemExit(main())
