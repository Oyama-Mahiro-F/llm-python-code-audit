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