# -*- coding: utf-8 -*-
# 由 auditor.harness 自动生成(alert_id=L-002);勿手工编辑。
import json
import sys

import os

# === 1. 业务源码片段(extract.py 产出)====================================
def run_command(user_cmd):
    command = "ls " + user_cmd
    os.system(command)
    return 0


# === 2. mock 桩(mock_gen.py 产出)=======================================
CAPTURED = {'sink_api': 'os.system', 'calls': []}

def _fake_system(cmd):
    CAPTURED['calls'].append({'args': str(cmd)})
    return 0

def _install_mock():
    import os
    os.system = _fake_system
_install_mock()

# === 3. 送入 payload,触发 sink ==========================================
PAYLOAD = 'zxq-demo-marker; echo pwned'
_result = {"captured": None, "payload": PAYLOAD, "error": None}
try:
    _fn = globals()['run_command']
    _fn(PAYLOAD)
except Exception as _e:  # 业务代码自身异常也完整记录,由判定器归因
    _result["error"] = type(_e).__name__ + ": " + str(_e)
_result["captured"] = CAPTURED

sys.stdout.write("@@RESULT@@" + json.dumps(_result, ensure_ascii=False))
sys.stdout.write("\n")
