"""Reuse only compilation/imports in one disposable fixture's model interpreter."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
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
    if args[0] not in ('sync', 'systemctl') or not args[1]:
        raise ValueError('invalid fixture model admission')
    return args


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
        payload = execute(code, model, database, log, args)
        if sink.write(payload) != len(payload):
            raise OSError('short fixture response')
        sink.flush()


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit(64)
    serve(*sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer)
