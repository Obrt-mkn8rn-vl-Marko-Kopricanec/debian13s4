"""Fixed private IP inventories with actual process metadata and live routes."""

from pathlib import Path
import shlex

from fixture_bus import condition
from fixture_dispatch import script as fixed_script, text


def script(ledger, replies, dynamic, fallback):
    if not isinstance(fallback, Path) or not fallback.is_absolute():
        raise ValueError('fixture requires an absolute route dispatcher')
    quoted_fallback = shlex.quote(text(str(fallback)))
    if type(dynamic) is not tuple or not dynamic or type(replies) is not dict or not replies:
        raise ValueError('fixture requires fixed inventory and route queries')
    commands = [*replies, *dynamic]
    for arguments in commands: condition(arguments)
    if len(commands) != len(set(commands)):
        raise ValueError('fixture inventory and route queries must be disjoint')
    original = fixed_script(ledger, 'ip', replies)
    marker = "fixture_entry='['"
    assert original.count(marker) == 1
    preamble, remainder = original.split(marker, 1)
    offset = remainder.index('\nif [[')
    dispatch = remainder[offset:]
    environment = '''fixture_environment=()
while IFS= read -r -d '' fixture_variable || [[ -n $fixture_variable ]]; do
    [[ $fixture_variable == *=* ]] || exit 1
    fixture_name=${fixture_variable%%=*}
    [[ $fixture_name =~ ^[a-zA-Z_][a-zA-Z_0-9]*$ ]] || exit 1
    fixture_environment+=("$fixture_variable")
done <"/proc/$BASHPID/environ"
'''
    live = ''.join(f'if {condition(arguments)}; then\n'
                   f'    exec /usr/bin/env -i -- "${{fixture_environment[@]}}" {quoted_fallback} "$@"\n'
                   'fi\n' for arguments in dynamic)
    ledger_body = '''IFS= read -r fixture_stat <"/proc/$BASHPID/stat" || exit 1
[[ $fixture_stat == "$BASHPID ("* ]] || exit 1
fixture_tail=${fixture_stat##*) }
[[ $fixture_tail != "$fixture_stat" ]] || exit 1
IFS=' ' read -r -a fixture_fields <<<"$fixture_tail"
[[ ${#fixture_fields[@]} -ge 4 ]] || exit 1
fixture_session=${fixture_fields[3]}
[[ $fixture_session =~ ^[1-9][0-9]*$ ]] || exit 1
fixture_entry='{"argv":['
fixture_separator=''
for fixture_argument in "$@"; do
    fixture_json "$fixture_argument"
    fixture_entry+=$fixture_separator$fixture_encoded
    fixture_separator=','
done
fixture_entry+='],"env":{'
fixture_separator=''
for fixture_variable in "${fixture_environment[@]}"; do
    fixture_name=${fixture_variable%%=*}
    fixture_json "$fixture_name"
    fixture_entry+=$fixture_separator$fixture_encoded:
    fixture_json "${fixture_variable#*=}"
    fixture_entry+=$fixture_encoded
    fixture_separator=','
done
fixture_entry+='},"pid":'$BASHPID',"sid":'$fixture_session'}'
'''
    delivery = f'printf \'%s\\n\' "$fixture_entry" >>{shlex.quote(text(str(ledger)))} || exit 1\n'
    return preamble + environment + live + ledger_body + delivery + dispatch
