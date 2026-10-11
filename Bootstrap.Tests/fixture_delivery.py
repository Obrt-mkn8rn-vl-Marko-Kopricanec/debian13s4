"""Reuse only compilation/imports in one disposable fixture's model interpreter."""

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import stat
import sys
import traceback


LIMIT = 65536


def field(stream, remaining, initial=False):
    data = bytearray()
    while len(data) < remaining:
        byte = stream.read(1)
        if not byte:
            if initial and not data:
                return None
            raise ValueError('incomplete fixture request')
        if byte == b'\0':
            return bytes(data)
        data.extend(byte)
    raise ValueError('fixture request exceeds its byte limit')


def request(stream):
    count = field(stream, 4, initial=True)
    if count is None:
        return None
    if not count.isdigit() or str(int(count)).encode() != count or not 2 <= int(count) <= 64:
        raise ValueError('invalid fixture argument count')
    remaining = LIMIT
    args = []
    for _ in range(int(count)):
        item = field(stream, remaining)
        remaining -= len(item) + 1
        # The maintained model uses UTF-8 paths and logical strings, not byte IO.
        args.append(item.decode('utf-8'))
    if args[0] not in ('sync', 'systemctl', 'trust') or not args[1]:
        raise ValueError('invalid fixture model admission')
    if args[0] == 'trust' and len(args) != 2:
        raise ValueError('private trust request accepts one path')
    return args


def trusted(root, path):
    # Fresh lstat of EVERY component on EVERY request, never a cached verdict.
    # Equivalent to the private harness's -e/!-L/-O/mode/ancestry grammar only;
    # this is not production root trust, hostile mount containment or atomicity.
    root = str(root)
    if (type(path) is not str or not root.startswith('/') or
        (path != root and not path.startswith(root + '/')) or
        '/./' in path or path.endswith('/.') or '/../' in path or
        path.endswith('/..') or '//' in path):
        return False
    while True:
        try:
            fact = os.lstat(path)
        except OSError:
            return False
        if stat.S_ISLNK(fact.st_mode) or fact.st_uid != os.geteuid() or fact.st_mode & 0o022:
            return False
        if path == root:
            return True
        path = path.rsplit('/', 1)[0]


def execute(code, model, database, log, args):
    stdout = io.StringIO()
    stderr = io.StringIO()
    previous = sys.argv
    status = 0
    try:
        sys.argv = [str(model), str(database), str(log), *args]
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                # Fresh globals and actual disk reads on EVERY invocation. No
                # state, snapshot, event or fault result survives in this scope.
                exec(code, {'__name__': '__main__', '__file__': str(model)})
            except SystemExit as error:
                if error.code is not None:
                    if type(error.code) is int and 0 <= error.code <= 255:
                        status = error.code
                    else:
                        print(error.code, file=sys.stderr)
                        status = 1
            except Exception:
                traceback.print_exc()
                status = 1
    finally:
        sys.argv = previous
    outputs = [value.getvalue().encode('utf-8') for value in (stdout, stderr)]
    if any(len(value) > LIMIT or b'\0' in value for value in outputs):
        raise ValueError('invalid fixture response')
    return str(status).encode() + b'\0' + outputs[0] + b'\0' + outputs[1] + b'\0'


def serve(model, database, log, source, sink):
    code = compile(Path(model).read_text(), str(model), 'exec')
    while (args := request(source)) is not None:
        if args[0] == 'trust':
            payload = (b'0' if trusted(Path(database).parent, args[1]) else b'1') + b'\0\0\0'
        else:
            payload = execute(code, model, database, log, args)
        if sink.write(payload) != len(payload):
            raise OSError('short fixture response')
        sink.flush()


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit(64)
    serve(*sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer)
