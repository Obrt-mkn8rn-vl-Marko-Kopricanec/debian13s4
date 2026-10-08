"""Generate a builtin-only child for fixed private UTF-8 fixture replies."""

import json
from pathlib import Path
import shlex


def text(value):
    if type(value) is not str or '\0' in value:
        raise ValueError('fixture requires NUL-free strings')
    value.encode('utf-8', errors='strict')
    return value


def script(ledger, kind, replies):
    if not isinstance(ledger, Path) or not ledger.is_absolute():
        raise ValueError('fixture requires an absolute ledger path')
    if type(replies) is not dict or not replies:
        raise ValueError('fixture requires fixed replies')
    quoted_ledger = shlex.quote(text(str(ledger)))
    encoded_kind = shlex.quote(json.dumps(text(kind)))
    body = [f'''#!/bin/bash -p
set -eu -o pipefail
export LC_ALL=C
# JSON quote actual argv bytes; native callers use valid UTF-8 strings.
fixture_json() {{
    local value=$1 character ordinal escaped index
    fixture_encoded='"'
    for ((index=0; index<${{#value}}; index++)); do
        character=${{value:index:1}}
        case "$character" in
            '"') fixture_encoded+='\\"' ;;
            \\\\) fixture_encoded+="\\\\\\\\" ;;
            *)
                printf -v ordinal '%d' "'$character"
                if ((ordinal < 32)); then
                    printf -v escaped '\\\\u%04x' "$ordinal"
                    fixture_encoded+=$escaped
                else
                    fixture_encoded+=$character
                fi
                ;;
        esac
    done
    fixture_encoded+='"'
}}
fixture_entry='['{encoded_kind}',['
fixture_separator=''
for fixture_argument in "$@"; do
    fixture_json "$fixture_argument"
    fixture_entry+=$fixture_separator$fixture_encoded
    fixture_separator=','
done
fixture_entry+='],{{}}]'
printf '%s\\n' "$fixture_entry" >>{quoted_ledger} || exit 1
''']
    for arguments, reply in replies.items():
        if type(arguments) is not tuple or not arguments:
            raise ValueError('fixture requires nonempty argument tuples')
        conditions = ' && '.join(f'${{{index}}} == {shlex.quote(text(argument))}'
                                 for index, argument in enumerate(arguments, 1))
        body.append(f'if [[ $# -eq {len(arguments)} ]] && [[ {conditions} ]]; then\n'
                    f"    printf '%s' {shlex.quote(text(reply))}\n"
                    '    exit 0\nfi\n')
    body.append('exit 1\n')
    return ''.join(body)
