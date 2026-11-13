CAPTURED = {'sink_api': 'os.system', 'calls': []}

def _fake_system(cmd):
    CAPTURED['calls'].append({'args': str(cmd)})
    return 0

def _install_mock():
    import os
    os.system = _fake_system