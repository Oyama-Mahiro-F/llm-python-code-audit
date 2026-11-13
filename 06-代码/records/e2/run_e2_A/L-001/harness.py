# -*- coding: utf-8 -*-
# 由 auditor.harness 自动生成(alert_id=L-001);勿手工编辑。
import json
import sys

import builtins

# === 1. 业务源码片段(extract.py 产出)====================================
def read_file(user_path):
    path = "/var/data/" + user_path
    with open(path) as f:
        return f.read()


# === 2. mock 桩(mock_gen.py 产出)=======================================
CAPTURED = {'sink_api': 'builtins.open', 'calls': []}

class _FakeFile:
    def __init__(self, path):
        self._path = path
    def read(self):
        return ''
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False

def _fake_open(file=None, *args, **kwargs):
    CAPTURED['calls'].append({'args': str(file)})
    return _FakeFile(file)

def _install_mock():
    import builtins
    builtins.open = _fake_open
_install_mock()

# === 3. 送入 payload,触发 sink ==========================================
PAYLOAD = '../../etc/passwd-zxq-demo-marker'
_result = {"captured": None, "payload": PAYLOAD, "error": None}
try:
    _fn = globals()['read_file']
    _fn(PAYLOAD)
except Exception as _e:  # 业务代码自身异常也完整记录,由判定器归因
    _result["error"] = type(_e).__name__ + ": " + str(_e)
_result["captured"] = CAPTURED

sys.stdout.write("@@RESULT@@" + json.dumps(_result, ensure_ascii=False))
sys.stdout.write("\n")
