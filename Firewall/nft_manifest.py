#!/usr/bin/python3
"""Compare nft SOURCE representation with this compiler's intended policy.

Only internally observed, trusted topology may establish an intended policy.
This standalone comparison does not authenticate that input, claim ownership,
install anything, or establish native semantic/enforcement compatibility.
Unsupported representations fail closed rather than becoming equivalent.
"""

import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import sys


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


POLICY = module('debian13s4_nft_manifest_compiler', 'policy.py')
STATE = module('debian13s4_nft_manifest_state', 'nft_state.py')
KERNEL, Pending = STATE.KERNEL, STATE.Pending
ATTEMPT_SECONDS = 10
TOKEN = re.compile(r'"[A-Za-z0-9_.-]+"|==|[{}(),&|]|[^\s{}(),&|]+')
SYMBOLS = {
    'state': {'invalid': 1, 'established': 2, 'related': 4, 'new': 8},
    'direction': {'original': 0, 'reply': 1}, 'nfproto': {'ipv4': 2, 'ipv6': 10},
    'flags': {'fin': 1, 'syn': 2, 'rst': 4, 'ack': 16},
    'icmp': {'destination-unreachable': 3, 'time-exceeded': 11, 'parameter-problem': 12},
    'icmpv6': {'destination-unreachable': 1, 'packet-too-big': 2, 'time-exceeded': 3,
               'parameter-problem': 4, 'mld-listener-query': 130, 'mld-listener-report': 131,
               'mld-listener-done': 132, 'nd-router-solicit': 133, 'nd-router-advert': 134,
               'nd-neighbor-solicit': 135, 'nd-neighbor-advert': 136, 'mld2-listener-report': 143},
}


def tokens(text):
    # Dots inside address/name atoms are not separators: compiler concat has spaces.
    words = TOKEN.findall(text)
    if ''.join(words) != re.sub(r'\s+', '', text):
        raise Pending('unsupported compiler tokenization')
    return words


class Reader:
    def __init__(self, text):
        self.words = tokens(text)
        self.position = 0

    def take(self):
        if self.position >= len(self.words):raise Pending('incomplete compiler expression')
        word = self.words[self.position];self.position += 1
        return word

    def want(self, value):
        if self.take() != value:raise Pending('unsupported compiler expression')

    def peek(self):
        return self.words[self.position] if self.position < len(self.words) else None


def scalar(word, datatype=None):
    if word.startswith('"') and word.endswith('"'):return word[1:-1]
    if word.startswith('@') and word[1:] in STATE.SET_TYPES:return word
    if datatype in SYMBOLS:
        if word not in SYMBOLS[datatype]:raise Pending('unsupported compiler symbol')
        return SYMBOLS[datatype][word]
    if word.isdecimal():return int(word)
    try:
        if '/' in word:
            prefix = ipaddress.ip_network(word, strict=True)
            return {'prefix': {'addr': str(prefix.network_address), 'len': prefix.prefixlen}}
        return str(ipaddress.ip_address(word))
    except ValueError:
        if POLICY.MAC.fullmatch(word):return word
        raise Pending('unsupported compiler constant') from None


def value(reader, datatype=None):
    if reader.peek() == '{':
        reader.take();items = [scalar(reader.take(), datatype)]
        while reader.peek() == ',':reader.take();items.append(scalar(reader.take(), datatype))
        reader.want('}')
        return {'set': items}
    return scalar(reader.take(), datatype)


def selector(reader):
    word = reader.take()
    if word in ('iifname', 'oifname'):
        return {'meta': {'key': word}}, None
    if word == 'meta':
        reader.want('nfproto');return {'meta': {'key': 'nfproto'}}, 'nfproto'
    if word == 'ct':
        key = reader.take()
        if key == 'original':
            reader.want('proto-dst');return {'ct': {'key': 'proto-dst', 'dir': 'original'}}, None
        if key not in ('state', 'direction'):raise Pending('unsupported compiler conntrack selector')
        return {'ct': {'key': key}}, key
    if word in ('ip', 'ip6', 'ether', 'udp', 'tcp', 'icmp', 'icmpv6'):
        field = reader.take()
        allowed = {'ip': {'saddr', 'daddr'}, 'ip6': {'saddr', 'daddr', 'hoplimit'}, 'ether': {'saddr'},
                   'udp': {'sport', 'dport'}, 'tcp': {'sport', 'dport', 'flags'},
                   'icmp': {'type'}, 'icmpv6': {'type', 'code'}}
        if field not in allowed[word]:raise Pending('unsupported compiler payload selector')
        datatype = 'flags' if field == 'flags' else word if field == 'type' else None
        return {'payload': {'protocol': word, 'field': field}}, datatype
    raise Pending('unsupported compiler selector')


def expression(text):
    reader, result = Reader(text), []
    while reader.peek() not in (None, 'counter'):
        left, datatype = selector(reader)
        if reader.peek() == '.':
            parts = [left]
            while reader.peek() == '.':
                reader.take();part, _ = selector(reader);parts.append(part)
                if len(parts) > 3:raise Pending('unsupported compiler concatenation')
            left = {'concat': parts};datatype = None
        if reader.peek() == '&':
            if datatype != 'flags':raise Pending('unsupported compiler bit operation')
            reader.take();reader.want('(');mask = scalar(reader.take(), 'flags')
            while reader.peek() == '|':reader.take();mask |= scalar(reader.take(), 'flags')
            reader.want(')');reader.want('==');left = {'&': [left, mask]}
        right = value(reader, datatype)
        result.append({'match': {'op': 'in' if datatype == 'state' else '==', 'left': left, 'right': right}})
    reader.want('counter');verdict = reader.take()
    if verdict not in ('accept', 'drop') or reader.peek() is not None:raise Pending('unsupported compiler terminal statement')
    return [*result, {'counter': {}}, {verdict: None}]


def operand_type(value):
    if type(value) is not dict:return None
    if 'concat' in value:return [operand_type(item) for item in value['concat']]
    if '&' in value:return operand_type(value['&'][0])
    if 'meta' in value and value['meta'].get('key') in ('iifname', 'oifname'):return 'ifname'
    if 'payload' in value:
        payload = value['payload']
        if payload.get('field') in ('saddr', 'daddr'):
            return {'ip': 'ipv4_addr', 'ip6': 'ipv6_addr', 'ether': 'ether_addr'}.get(payload.get('protocol'))
    return None


def canonical_expression(value, datatype=None):
    if type(value) in (str, int):
        if type(value) is int:STATE.uint(value, True)
        return value
    if type(value) is not dict or len(value) != 1:raise Pending('unsupported intended expression representation')
    kind, data = next(iter(value.items()))
    if kind in ('meta', 'ct', 'payload'):
        # Equality with the generated manifest checks every selector key/value.
        if type(data) is not dict or any(type(k) is not str or type(v) is not str for k, v in data.items()):
            raise Pending('unsupported intended selector representation')
        return value
    if kind == 'prefix':
        if datatype not in ('ipv4_addr', 'ipv6_addr'):raise Pending('prefix outside an address operand')
        KERNEL.known(data, {'addr', 'len'}, {'addr', 'len'})
        if type(data['addr']) is not str or type(data['len']) is not int:raise Pending('untyped intended prefix')
        try:
            prefix = ipaddress.ip_network(f"{data['addr']}/{data['len']}", strict=True)
        except ValueError as error:raise Pending('invalid intended prefix') from error
        if prefix.version != (4 if datatype == 'ipv4_addr' else 6) or str(prefix.network_address) != data['addr']:
            raise Pending('wrong family or noncanonical intended prefix')
        return str(prefix.network_address) if prefix.prefixlen == prefix.max_prefixlen else value
    if kind in ('set', 'concat', '|', '&'):
        if type(data) is not list or not data or len(data) > POLICY.MAX_ITEMS:raise Pending('unsupported intended expression list')
        if kind == 'concat' and datatype is not None:
            if type(datatype) is not list or len(datatype) != len(data):raise Pending('untyped intended concatenation')
            items = [canonical_expression(item, part) for item, part in zip(data, datatype)]
        else:
            items = [canonical_expression(item, datatype if kind == 'set' else None) for item in data]
        if kind == '|':
            if any(type(item) is not int for item in items):raise Pending('untyped intended bitmask')
            mask = 0
            for item in items:mask |= item
            return mask
        if kind == 'set':
            keys = [STATE.encoded(item) for item in items]
            if len(set(keys)) != len(keys):raise Pending('duplicate intended anonymous element')
            items = [item for _, item in sorted(zip(keys, items), key=lambda pair: pair[0])]
        if kind == '&' and (len(items) != 2 or type(items[1]) is not int):raise Pending('unsupported intended bitmask selector')
        return {kind: items}
    raise Pending('unsupported intended expression object')


def canonical_policy(policy):
    # STATE.project has already admitted the complete structural SOURCE envelope.
    result = json.loads(STATE.encoded(policy))
    if result['table'].get('flags') == []:result['table'].pop('flags')
    for row in result['sets'].values():
        elements = row.get('elem', [])
        if type(elements) is not list:raise Pending('unsupported intended set element container')
        elements = [canonical_expression(item, row['type']) for item in elements]
        keys = [STATE.encoded(item) for item in elements]
        if len(set(keys)) != len(keys):raise Pending('duplicate intended named element')
        row['elem'] = [item for _, item in sorted(zip(keys, elements), key=lambda pair: pair[0])]
    for rules in result['rules'].values():
        for rule in rules:
            for statement in rule['expr']:
                if 'match' in statement:
                    match = statement['match']
                    match['left'] = canonical_expression(match['left'])
                    match['right'] = canonical_expression(match['right'], operand_type(match['left']))
    return result


def expected(raw):
    text = POLICY.compile_policy(raw)
    lines = text.splitlines()
    if lines[:2] != ['destroy table inet debian13s4', 'table inet debian13s4 {'] or lines[-1:] != ['}']:
        raise Pending('unsupported compiler transaction frame')
    objects = [{'metainfo': {'version': '1.1.3', 'release_name': 'expected SOURCE shape', 'json_schema_version': 1}},
               {'table': {'family': 'inet', 'name': STATE.TABLE, 'handle': 1}}]
    chain, seen, handle = None, set(), 2
    for line in lines[2:-1]:
        matched = re.fullmatch(r'    set (\w+) \{ type ([\w .]+); flags (constant(?:, interval)?);(?: elements = \{ (.+) \};)? \}', line)
        if matched and chain is None:
            name, datatype, flags, entries = matched.groups()
            if name not in STATE.SET_TYPES:raise Pending('unsupported compiler set identity')
            datatype = datatype.split(' . ') if ' . ' in datatype else datatype
            elements = []
            for entry in entries.split(', ') if entries else []:
                parts = entry.split(' . ');items = [scalar(part) for part in parts]
                elements.append(items[0] if len(items) == 1 else {'concat': items})
            objects.append({'set': {'family': 'inet', 'table': STATE.TABLE, 'name': name, 'handle': handle,
                                    'type': datatype, 'flags': flags.split(', '), 'elem': elements}})
        elif line.startswith('    chain ') and chain is None:
            matched = re.fullmatch(r'    chain (input|forward|output) \{', line)
            if matched is None or matched[1] in seen:raise Pending('unsupported compiler chain frame')
            chain = matched[1];seen.add(chain)
            objects.append({'chain': {'family': 'inet', 'table': STATE.TABLE, 'name': chain, 'handle': handle,
                                      'type': 'filter', 'hook': chain, 'prio': 0, 'policy': 'drop'}})
        elif chain is not None and line == f'        type filter hook {chain} priority 0; policy drop;':
            continue
        elif chain is not None and line == '    }':chain = None
        elif chain is not None and line.startswith('        '):
            statements = expression(line[8:])
            statements[-2] = {'counter': {'packets': 0, 'bytes': 0}}
            objects.append({'rule': {'family': 'inet', 'table': STATE.TABLE, 'chain': chain, 'handle': handle, 'expr': statements}})
        else:raise Pending('unsupported compiler declaration or frame')
        handle += 1
    if chain is not None or seen != set(STATE.CHAINS):raise Pending('incomplete compiler chain frame')
    projected = STATE.project({'nftables': objects})
    policy = canonical_policy(projected['policy'])
    return {'policy': policy, 'fingerprint': hashlib.sha256(STATE.encoded(policy)).hexdigest(),
            'compiler_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
            'topology_sha256': hashlib.sha256(raw).hexdigest()}


def verify(raw, query=STATE.NFT.native_query, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):raise Pending('invalid intended policy deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    manifest = expected(raw)
    if KERNEL.now() >= end:raise Pending('intended policy preparation expired')
    observed = STATE.observe(query=query, scope=scope, deadline=end)
    policy = canonical_policy(observed['policy'])
    if policy != manifest['policy']:raise Pending('observed SOURCE does not match compiler intention')
    last = scope()
    if type(last) is not int or last != observed['namespace'] or KERNEL.now() >= end:
        raise Pending('intended policy comparison context changed or expired')
    return {'schema': 'debian13s4-nft-compiler-match-1', 'profile': 'numeric-static-compiler-source-1',
            'namespace': observed['namespace'], 'source': observed['source'], 'identity': observed['identity'],
            'statistics': observed['statistics'], **manifest}


def main():
    if len(sys.argv) != 1:return 64
    try:
        sink = getattr(sys.stdout, 'buffer', None)
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('intended policy requires a binary output sink')
        payload = STATE.encoded(verify(sys.stdin.buffer.read(POLICY.MAX_INPUT + 1))) + b'\n'
        if len(payload) > STATE.MAX_OUTPUT:raise Pending('intended policy publication exceeds bound')
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):raise Pending('intended policy output was not fully written')
        sink.flush();return 0
    except (OSError, ValueError, AttributeError, KERNEL.subprocess.TimeoutExpired) as error:
        print(f'debian13s4 nft compiler comparison pending: {error}', file=sys.stderr);return 75


if __name__ == '__main__':raise SystemExit(main())
