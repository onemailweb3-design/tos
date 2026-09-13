"""Executable specification oracle only; not a production codec or signer."""
import hashlib
import struct
import zlib

MAX_OBJECT = 32 * 1024 * 1024
MAX_WEIGHT = ((1 << 64) - 1) // 3
FORMATS = {'u8': '>B', 'u16': '>H', 'u32': '>I', 'u64': '>Q', 'i32': '>i'}
# The machine-readable schema is the only source of field order and bounds.
import json
from pathlib import Path
SCHEMA = json.loads((Path(__file__).resolve().parents[2] /
                    'doc/validator-auth-p0/canonical-schema.json').read_text())
SCHEMAS = {name: (definition['tag'], ' '.join(n+':'+t for n,t in definition['fields']))
           for name, definition in SCHEMA['types'].items()}

class Refusal(ValueError):
    pass

def require(ok, code):
    if not ok:
        raise Refusal(code)

def checked_weight(acc, weight):
    require(0 < weight <= MAX_WEIGHT - acc, 'weight')
    return acc + weight

def fields(kind):
    return [field.split(':', 1) for field in SCHEMAS[kind][1].split()]

def encode(kind, obj):
    out = bytearray()
    def put(t, v):
        if t in FORMATS:
            require(type(v) is int, 'integer-type')
            try:
                out.extend(struct.pack(FORMATS[t], v))
            except struct.error as exc:
                raise Refusal('integer-range') from exc
        elif t == 'h' or t.startswith('b'):
            require(type(v) is bytes, 'byte-type')
            if t == 'h':
                require(len(v) == 32, 'hash-length')
            else:
                require(len(v) <= int(t[1:]), 'blob-bound')
                put('u32', len(v))
            out.extend(v)
        elif t.startswith('l'):
            width, limit, child = t[1:].split('/')
            require(type(v) is list and len(v) <= int(limit), 'list-bound')
            put('u'+width, len(v))
            for item in v:
                put(child, item)
        else:
            tag, _ = SCHEMAS[t]
            fs = fields(t)
            require(type(v) is dict and set(v) == {n for n, _ in fs}, 'fields')
            if tag:
                out.extend(tag.encode('ascii') + b'\0\1\0\0')
            for name, child in fs:
                put(child, v[name])
        require(len(out) <= MAX_OBJECT, 'object-bound')
    put(kind, obj)
    return bytes(out)

def decode(kind, raw):
    require(type(raw) is bytes and len(raw) <= MAX_OBJECT, 'object-bound')
    at = 0
    def take(n):
        nonlocal at
        require(n <= len(raw) - at, 'truncated')
        result = raw[at:at+n]
        at += n
        return result
    def get(t):
        if t in FORMATS:
            return struct.unpack(FORMATS[t], take(struct.calcsize(FORMATS[t])))[0]
        if t == 'h':
            return take(32)
        if t.startswith('b'):
            n = get('u32')
            require(n <= int(t[1:]), 'blob-bound')
            return take(n)
        if t.startswith('l'):
            width, limit, child = t[1:].split('/')
            n = get('u'+width)
            require(n <= int(limit), 'list-bound')
            return [get(child) for _ in range(n)]
        tag, _ = SCHEMAS[t]
        if tag:
            require(take(4) == tag.encode('ascii'), 'tag')
            require(get('u16') == 1, 'version')
            require(get('u16') == 0, 'flags')
        return {name: get(child) for name, child in fields(t)}
    result = get(kind)
    require(at == len(raw), 'trailing')
    return result

def digest(label, data):
    return hashlib.sha256(b'TOS/P0/' + label.encode('ascii') + b'/v1\0' + data).digest()

def object_id(kind, value):
    return digest(kind, encode(kind, value))

def keyref(key):
    return {**{n: key[n] for n in ('suite', 'parameters', 'epoch')}, 'key_id': object_id('key', key)}

def statement(duty, record):
    refs = [{n: c[n] for n in ('suite', 'parameters', 'epoch', 'key_id')} for c in record['components']]
    return encode('statement', {'duty': duty, 'identity': record['identity'], 'keys': refs})

def constructor(schema):
    return struct.pack('<I', zlib.crc32(schema.encode('ascii')))

CANDIDATE = constructor('consensus.candidateId slot:int hash:int256 = consensus.CandidateId')
VOTE = {r: constructor(f'consensus.simplex.{name}Vote id:consensus.CandidateId = consensus.simplex.UnsignedVote')
        for r, name in ((2, 'notarize'), (3, 'finalize'))}
SKIP = constructor('consensus.simplex.skipVote slot:int = consensus.simplex.UnsignedVote')

def validate_payload(duty, payload):
    role, position = duty['role'], duty['position']
    require(duty['payload_hash'] == digest('payload', bytes([role])+payload), 'payload-hash')
    if role == 5:
        intent = decode('update', payload)
        require(1 <= intent['operation'] <= 7 and intent['nonce'] == position, 'admin-payload')
        return  # Ownership, CAS and inclusion-time authorization are apply gates.
    require(role in (1, 2, 3, 4) and position < 1 << 32, 'role-position')
    expected = {1: (40, CANDIDATE, 4), 2: (44, VOTE[2]+CANDIDATE, 8),
                3: (44, VOTE[3]+CANDIDATE, 8), 4: (8, SKIP, 4)}[role]
    size, prefix, offset = expected
    require(len(payload) == size and payload.startswith(prefix), 'payload-type')
    require(struct.unpack('<I', payload[offset:offset+4])[0] == position, 'payload-position')

def validate_c0_policy(policy):
    encode('policy', policy)
    require(policy['phase'] == 0 and policy['suites'] == [{'suite': 1, 'parameters': 1}], 'c0-policy')
    require(policy['revision'] >= 1 and policy['max_envelope'] == 4096
            and policy['max_certificate'] == 524288, 'c0-limits')

def verify_c0(cert, committee, policy, expected_duty, verifier):
    """Real C0 verification oracle; inputs must be authenticated by its caller."""
    validate_c0_policy(policy)
    encode('committee', committee)
    require(committee['policy'] == object_id('policy', policy), 'registry-policy')
    members = committee['members']
    ids = [m['identity'] for m in members]
    require(ids and ids == sorted(set(ids)) and bytes(32) not in ids, 'registry-identities')
    stakes = [m['stake_id'] for m in members]
    require(len(stakes) == len(set(stakes)) and bytes(32) not in stakes, 'registry-stakes')
    total = 0
    for m in members:
        total = checked_weight(total, m['weight'])
        require([(k['role'], k['suite'], k['parameters']) for k in m['keys']]
                == [(r, 1, 1) for r in range(1, 6)], 'registry-keys')
        for k in m['keys']:
            require(k['identity'] == m['identity'] and k['epoch'] >= 1
                    and k['valid_from'] <= committee['anchor_mc'] < k['valid_until'], 'key-validity')
            require(k['capacity_domain'] == bytes(32) and k['capacity_limit'] == 0, 'c0-capacity')
            require(verifier.admit(k['public_key']), 'public-key')
    require(len(encode('certificate', cert)) <= policy['max_certificate'], 'certificate-budget')
    duty = cert['duty']
    require(duty == expected_duty, 'expected-context')
    require(duty['committee'] == object_id('committee', committee)
            and duty['policy'] == object_id('policy', policy), 'context-binding')
    require(all(duty[n] == committee[n] for n in ('workchain', 'shard', 'anchor_mc', 'catchain')), 'scope')
    validate_payload(duty, cert['payload'])
    rows = cert['records']
    signers = [r['identity'] for r in rows]
    require(signers and signers == sorted(set(signers)) and len(rows) <= len(members) <= 400, 'signer-order')
    roster = {m['identity']: m for m in members}
    admitted = []
    weight = 0
    for row in rows:
        require(row['identity'] in roster, 'unknown-signer')
        member = roster[row['identity']]
        require(len(row['components']) == 1, 'c0-components')
        component = row['components'][0]
        key = member['keys'][duty['role']-1]
        require({n: component[n] for n in ('suite', 'parameters', 'epoch', 'key_id')} == keyref(key), 'key-binding')
        require(len(component['signature']) == 64, 'signature-size')
        weight = checked_weight(weight, member['weight'])
        admitted.append((key['public_key'], statement(duty, row), component['signature']))
    require(3*weight >= 2*total, 'quorum')
    for key, message, signature in admitted:
        require(verifier.verify(key, message, signature), 'signature')
    return weight

def tl_frame(tag, raw):
    require(len(tag) == 4 and len(raw) <= min(MAX_OBJECT, (1 << 24)-1), 'tl-bound')
    prefix = bytes([len(raw)]) if len(raw) < 254 else b'\xfe'+len(raw).to_bytes(3, 'little')
    sized = prefix + raw
    return tag + sized + bytes((-len(sized)) % 4)

def tl_unframe(tag, wire):
    require(len(wire) >= 8 and wire[:4] == tag, 'tl-tag')
    first = wire[4]
    require(first != 255, 'tl-length')
    n, offset = (first, 5) if first < 254 else (int.from_bytes(wire[5:8], 'little'), 8)
    require(n <= MAX_OBJECT and (first < 254 or n >= 254), 'tl-length')
    end = offset+n
    require(len(wire) == end+(-(end-4)) % 4 and all(x == 0 for x in wire[end:]), 'tl-padding')
    return wire[offset:end]

def byte_tree(raw):
    require(1 <= len(raw) <= MAX_OBJECT, 'tree-bound')
    if len(raw) <= 120:
        return (0, raw)
    capacity = 120
    while len(raw) > 4*capacity:
        capacity *= 4
    return (1, len(raw), [byte_tree(raw[i:i+capacity]) for i in range(0, len(raw), capacity)])

def unbyte_tree(node):
    count = 0
    def walk(n, depth):
        nonlocal count
        count += 1
        require(depth <= 10 and count <= 400000, 'tree-budget')
        if type(n) is tuple and len(n) == 2 and n[0] == 0:
            require(type(n[1]) is bytes and 1 <= len(n[1]) <= 120, 'leaf')
            return n[1]
        require(type(n) is tuple and len(n) == 3 and n[0] == 1
                and type(n[1]) is int and 120 < n[1] <= MAX_OBJECT
                and type(n[2]) is list and 2 <= len(n[2]) <= 4, 'branch')
        parts, total = [], 0
        for child in n[2]:
            part = walk(child, depth+1)
            total += len(part)
            require(total <= n[1], 'tree-length')
            parts.append(part)
        require(total == n[1], 'tree-length')
        return b''.join(parts)
    raw = walk(node, 0)
    require(node == byte_tree(raw), 'tree-canonical')
    return raw

def reserve_vote(records, role, candidate):
    """Single-duty conflict model, not permission to vote or durable storage."""
    require(role in (1, 2, 3, 4, 5), 'role')
    if role in records:
        require(records[role] == candidate, 'conflict')
        return False
    require(not ((role == 3 and 4 in records) or (role == 4 and 3 in records)), 'conflict')
    other = {2: 3, 3: 2}.get(role)
    require(other not in records or records[other] == candidate, 'conflict')
    records[role] = candidate
    return True

def select_policy(policies, anchor):
    require(policies and policies[0]['effective_from'] == 0, 'policy-history')
    # The loop below only compares neighbours, so the first policy's own
    # revision and predecessor were never checked and a history could begin at
    # any revision or claim a predecessor. ACTIVATION.md fixes genesis at
    # revision 1 with a zero predecessor; a truncated history needs an
    # independently authenticated base supplied as input, not a weaker rule here.
    require(policies[0]['revision'] == 1 and policies[0]['previous'] == bytes(32), 'policy-history')
    for old, new in zip(policies, policies[1:]):
        require(new['effective_from'] > old['effective_from'] and new['revision'] == old['revision']+1
                and new['previous'] == object_id('policy', old), 'policy-history')
    eligible = [p for p in policies if p['effective_from'] <= anchor]
    require(bool(eligible), 'policy-history')
    return eligible[-1]
