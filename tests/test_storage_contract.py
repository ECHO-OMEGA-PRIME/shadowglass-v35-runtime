from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from storage import CommandStore


class Cursor:
    description = (("ok",),)

    def __init__(self) -> None:
        self.sql = ""

    def __enter__(self) -> "Cursor":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.sql = sql
        assert params == ()

    def fetchall(self) -> list[tuple[int]]:
        return [(1,)]


class Connection:
    def __init__(self) -> None:
        self.last = Cursor()
        self.closed = False

    @contextmanager
    def cursor(self):
        yield self.last

    def close(self) -> None:
        self.closed = True


def test_health_ping_is_constant_cost() -> None:
    connection = Connection()
    store = CommandStore("unused", connector=lambda _: connection)
    assert store.query("ping", (), limit=1) == [{"ok": 1}]
    assert connection.last.sql.strip() == "SELECT 1 AS ok"
    assert "count" not in connection.last.sql.lower()
    assert connection.closed is True
