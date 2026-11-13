CAPTURED = {'sink_api': 'sqlite3.Cursor.execute', 'calls': []}

class _FakeCursor:
    def execute(self, sql=None, params=None):
        CAPTURED['calls'].append({'args': str(sql), 'sanitized': params is not None})
        return self
    def fetchone(self):
        return None

class _FakeConnection:
    def cursor(self):
        return _FakeCursor()
    def close(self):
        return None

def _fake_connect(*args, **kwargs):
    return _FakeConnection()

def _install_mock():
    import sqlite3
    sqlite3.connect = _fake_connect