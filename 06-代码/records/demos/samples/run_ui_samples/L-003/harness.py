# -*- coding: utf-8 -*-
# 由 auditor.harness 自动生成(alert_id=L-003);勿手工编辑。
import json
import sys

import sqlite3

# === 1. 业务源码片段(extract.py 产出)====================================
DB_PATH = "app.db"

def open_db():
    conn = sqlite3.connect(DB_PATH)
    return conn

def get_user(username):
    conn = open_db()
    cursor = conn.cursor()
    query = f"SELECT id, email FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


# === 2. mock 桩(mock_gen.py 产出)=======================================
# --- mock 桩(模板生成,拦截 sqlite3 危险 sink)---
import json as _json

CAPTURED = {"sink_api": "sqlite3.Cursor.execute", "calls": []}


class _FakeCursor:
    def execute(self, sql=None, params=None):
        CAPTURED["calls"].append({
            "sql": sql if isinstance(sql, str) else repr(sql),
            "params": None if params is None else repr(params),
            "sanitized": params is not None,
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

_install_mock()

# === 3. 送入 payload,触发 sink ==========================================
PAYLOAD = "zxq-demo-marker' OR '1'='1"
_result = {"captured": None, "payload": PAYLOAD, "error": None}
try:
    _fn = globals()['get_user']
    _fn(PAYLOAD)
except Exception as _e:  # 业务代码自身异常也完整记录,由判定器归因
    _result["error"] = type(_e).__name__ + ": " + str(_e)
_result["captured"] = CAPTURED

sys.stdout.write("@@RESULT@@" + json.dumps(_result, ensure_ascii=False))
sys.stdout.write("\n")
