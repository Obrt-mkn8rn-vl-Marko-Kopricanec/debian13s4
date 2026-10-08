"""Generate fixed private bus replies, retaining Python for live JSON faults."""

from pathlib import Path
import shlex

from fixture_dispatch import script as fixed_script, text


def condition(arguments):
    if type(arguments) is not tuple or not arguments:
        raise ValueError('fixture requires nonempty fixed arguments')
    terms = ' && '.join(f'${{{index}}} == {shlex.quote(text(argument))}'
                        for index, argument in enumerate(arguments, 1))
    return f'[[ $# -eq {len(arguments)} ]] && [[ {terms} ]]'


def script(ledger, replies, pid, namespace, dynamic, fallback):
    """Only the declared exact queries may reach the retained live dispatcher."""
    if not isinstance(fallback, Path) or not fallback.is_absolute():
        raise ValueError('fixture requires an absolute live dispatcher')
    fallback_text = shlex.quote(text(str(fallback)))
    groups = (pid, namespace, dynamic)
    if any(type(group) is not tuple or not group for group in groups):
        raise ValueError('fixture requires fixed PID/namespace/live queries')
    if type(replies) is not dict or not replies:
        raise ValueError('fixture requires fixed static replies')
    commands = [*replies, *pid, *namespace, *dynamic]
    for arguments in commands: condition(arguments)
    if len(commands) != len(set(commands)):
        raise ValueError('fixture queries must be disjoint')
    source = fixed_script(ledger, 'bus', replies)
    header = 'export LC_ALL=C\n'
    assert source.count(header) == 1
    source = source.replace(header, header + '''# Retain the actual exec-time environment, rather than Bash's added variables.
fixture_environment=()
while IFS= read -r -d '' fixture_variable || [[ -n $fixture_variable ]]; do
    [[ $fixture_variable == *=* ]] || exit 1
    fixture_name=${fixture_variable%%=*}
    [[ $fixture_name =~ ^[a-zA-Z_][a-zA-Z_0-9]*$ ]] || exit 1
    fixture_environment+=("$fixture_variable")
done <"/proc/$BASHPID/environ"
''')
    marker = "fixture_entry='['"
    assert source.count(marker) == 1
    before, after = source.split(marker, 1)
    live = ''.join(f'if {condition(arguments)}; then\n'
                   f'    exec /usr/bin/env -i -- "${{fixture_environment[@]}}" {fallback_text} "$@"\n'
                   'fi\n' for arguments in dynamic)
    source = before + live + marker + after
    closure = "fixture_entry+='],{}]'\n"
    assert source.count(closure) == 1
    source = source.replace(closure, '''fixture_entry+='],{'
fixture_separator=''
for fixture_variable in "${fixture_environment[@]}"; do
    fixture_name=${fixture_variable%%=*}
    fixture_json "$fixture_name"
    fixture_entry+=$fixture_separator$fixture_encoded:
    fixture_json "${fixture_variable#*=}"
    fixture_entry+=$fixture_encoded
    fixture_separator=','
done
fixture_entry+='}]'
''')
    tail = 'exit 1\n'
    assert source.endswith(tail)
    source = source[:-len(tail)]
    for arguments in pid:
        source += (f'if {condition(arguments)}; then\n'
                   '    printf \'{"type": "u", "data": [%s]}\\n\' "$PPID"\n'
                   '    exit 0\nfi\n')
    for arguments in namespace:
        source += (f'if {condition(arguments)}; then\n'
                   '    fixture_namespace=$(/usr/bin/readlink /proc/self/ns/net) || exit 1\n'
                   '    [[ $fixture_namespace =~ ^net:\\[([1-9][0-9]*)\\]$ ]] || exit 1\n'
                   '    printf \'{"type": "v", "data": [{"type": "t", "data": %s}]}\\n\' "${BASH_REMATCH[1]}"\n'
                   '    exit 0\nfi\n')
    return source + tail
