#!/usr/bin/env python3
"""Provision root-only database and provider credentials without emitting values."""

from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


SOURCE = Path("/etc/echo/credentials/shadowglass-v7-publicsearch")
TARGET = Path("/etc/echo/credentials/shadowglass-v7-command")
ROLE = "cf_shadowglass_v7_command"
QUEUE_NAMES = {
    "shadowglass-ps-queue": "ps-queue-id",
    "shadowglass-tf-queue": "tf-queue-id",
    "shadowglass-tyler-queue": "tyler-queue-id",
}


def atomic_secret(path: Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value.strip() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, stat.S_IRUSR)
    finally:
        temporary.unlink(missing_ok=True)


def provider_get(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        document = json.loads(response.read())
    if not isinstance(document, dict) or document.get("success") is not True:
        raise RuntimeError("provider inventory request was unsuccessful")
    return document


def discover(account: str, token: str) -> dict[str, str]:
    root = f"https://api.cloudflare.com/client/v4/accounts/{account}/queues"
    matches: dict[str, list[str]] = {name: [] for name in QUEUE_NAMES}
    page = 1
    while True:
        url = root + "?" + urllib.parse.urlencode({"page": page, "per_page": 100})
        document = provider_get(url, token)
        for row in document.get("result") or []:
            name = row.get("queue_name") or row.get("name")
            queue_id = row.get("queue_id") or row.get("id")
            if name in matches and isinstance(queue_id, str) and queue_id:
                matches[name].append(queue_id)
        info = document.get("result_info") or {}
        if page >= int(info.get("total_pages") or page):
            break
        page += 1
    if any(len(values) != 1 for values in matches.values()):
        raise RuntimeError("recovered queue identities were not unique")
    return {QUEUE_NAMES[name]: values[0] for name, values in matches.items()}


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("credential provisioning requires root")
    account = (SOURCE / "cloudflare-account-id").read_text().strip()
    token = (SOURCE / "cloudflare-queue-token").read_text().strip()
    if not account or not token:
        raise RuntimeError("canonical provider credential is unavailable")
    queue_ids = discover(account, token)
    TARGET.mkdir(parents=True, exist_ok=True)
    os.chmod(TARGET, stat.S_IRWXU)
    password_path = TARGET / "database-password"
    password = password_path.read_text().strip() if password_path.exists() else secrets.token_urlsafe(36)
    escaped = password.replace("'", "''")
    sql = f"""
    DO $role$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{ROLE}') THEN
        CREATE ROLE {ROLE} LOGIN PASSWORD '{escaped}' NOSUPERUSER NOCREATEDB
          NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT 8;
      ELSE
        ALTER ROLE {ROLE} PASSWORD '{escaped}';
      END IF;
    END $role$;
    GRANT CONNECT ON DATABASE echo TO {ROLE};
    GRANT USAGE ON SCHEMA cf_shadowglass_v7_command, cf_shadowglass_v7_tyler TO {ROLE};
    GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA cf_shadowglass_v7_command TO {ROLE};
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA cf_shadowglass_v7_command TO {ROLE};
    GRANT SELECT ON ALL TABLES IN SCHEMA cf_shadowglass_v7_tyler TO {ROLE};
    GRANT UPDATE (status, updated_at) ON cf_shadowglass_v7_tyler.scrape_jobs TO {ROLE};
    """
    subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "echo", "-f", "-"],
        input=sql,
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    atomic_secret(password_path, password)
    atomic_secret(TARGET / "database-url", f"postgresql://{ROLE}:{urllib.parse.quote(password, safe='')}@127.0.0.1:5432/echo")
    atomic_secret(TARGET / "command-key", (TARGET / "command-key").read_text().strip() if (TARGET / "command-key").exists() else secrets.token_urlsafe(48))
    atomic_secret(TARGET / "cors-origins", "https://throne.echo-op.com,http://127.0.0.1")
    atomic_secret(TARGET / "cloudflare-account-id", account)
    atomic_secret(TARGET / "cloudflare-queue-token", token)
    for filename, queue_id in queue_ids.items():
        atomic_secret(TARGET / filename, queue_id)
    print(json.dumps({"ok": True, "credential_mode": "0400", "queue_match_count": 3}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

