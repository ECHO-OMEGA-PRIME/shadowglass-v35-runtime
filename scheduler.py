#!/usr/bin/env python3
"""Run one bounded scheduled-dispatch tick for explicitly enabled rows."""

from __future__ import annotations

import json

from app import get_runtime


def main() -> int:
    result = get_runtime().run_schedules(limit=25)
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

