# --- mock 桩(模板生成,拦截 sqlite3 危险 sink)---
import json as _json

CAPTURED = {"sink_api": "sqlite3.Cursor.execute", "calls": []}


class _FakeCursor:
    def execute(self, sql=None, params=None):
        CAPTURED["calls"].append({
            "sql": sql if isinstance(sql, str) else repr(sql),
            "params": None if params is None else repr(params),
        })
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _FakeConnection:
    def cursor(self):
        return _FakeCursor()


def _install_mock():
    import sqlite3
    sqlite3.connect = lambda *a, **k: _FakeConnection()
