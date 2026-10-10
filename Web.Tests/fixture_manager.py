"""Private UTF-8 manager delivery; cache compilation, never replies or state."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('web_bootstrap_delivery', ROOT / 'Bootstrap.Tests/fixture_delivery.py')
DELIVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELIVERY)
ACTIONS = frozenset(('systemctl', 'sync', 'package', 'audit'))


def compile_model(model):
    # The shared protocol supplies an unused log and a fixed envelope tag.
    # Remove only those two delivery fields before the ORIGINAL full model.
    prefix = 'import sys\nsys.argv = [sys.argv[0], sys.argv[1], *sys.argv[4:]]\n'
    return compile(prefix + Path(model).read_text(), str(model), 'exec')


def execute(code, model, root, args):
    if (type(args) is not list or not 1 <= len(args) <= 63 or
        any(type(arg) is not str or '\0' in arg for arg in args) or args[0] not in ACTIONS or
        sum(len(arg.encode('utf-8')) + 1 for arg in args) > DELIVERY.LIMIT - len('systemctl') - 1):
        raise ValueError('unsupported private web manager request')
    return DELIVERY.execute(code, model, root, Path(root) / 'events.jsonl', ['systemctl', *args])


def serve(model, root, source, sink):
    code = compile_model(model)
    while (args := DELIVERY.request(source)) is not None:
        if args[0] != 'systemctl':
            raise ValueError('unsupported private web manager envelope')
        payload = execute(code, model, root, args[1:])
        if sink.write(payload) != len(payload):
            raise OSError('short private web manager response')
        sink.flush()


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit(64)
    # Fourth shared-transport argument is a delivery-only log, never authority.
    serve(sys.argv[1], sys.argv[2], sys.stdin.buffer, sys.stdout.buffer)
