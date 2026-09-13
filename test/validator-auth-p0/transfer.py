"""Bounded public-object transfer oracle. Integrity never supplies authority."""
import hashlib
import reference as r

CHUNK = r.SCHEMA['limits']['chunk_bytes']
INLINE = r.SCHEMA['limits']['inline_bytes']
KINDS = {1: 'key', 2: 'policy', 3: 'committee', 4: 'certificate', 5: 'proof', 6: 'envelope', 7: 'update'}


def limit(kind):
    r.require(kind in KINDS, 'object-kind')
    return r.SCHEMA['limits']['boc_bytes'] if kind == 5 else r.MAX_OBJECT


def identifier(kind, raw):
    limit(kind)
    return r.digest(KINDS[kind], raw)


def manifest(raw, kind):
    r.require(INLINE < len(raw) <= limit(kind), 'manifest-length')
    oid = identifier(kind, raw)
    chunks = [raw[i:i+CHUNK] for i in range(0, len(raw), CHUNK)]
    return dict(kind=kind, byte_length=len(raw), object_id=oid,
                chunk_hashes=[r.digest('object-chunk', oid+bytes([i])+part) for i, part in enumerate(chunks)])


def value(raw, kind):
    r.require(type(raw) is bytes and 0 < len(raw) <= limit(kind), 'object-length')
    return dict(kind=kind, inline=raw if len(raw) <= INLINE else b'',
                reference=[] if len(raw) <= INLINE else [manifest(raw, kind)])


def validate_manifest(ref):
    r.encode('object_ref', ref)
    r.require(INLINE < ref['byte_length'] <= limit(ref['kind']), 'manifest-length')
    r.require(len(ref['chunk_hashes']) == (ref['byte_length']+CHUNK-1)//CHUNK, 'manifest-count')


def validate_value(v, kind):
    r.encode('object_value', v)
    r.require(v['kind'] == kind, 'object-kind')
    limit(kind)
    r.require(bool(v['inline']) != bool(v['reference']), 'object-representation')
    if v['reference']:
        validate_manifest(v['reference'][0])
        r.require(v['reference'][0]['kind'] == kind, 'object-kind')


def object_id(v, kind):
    validate_value(v, kind)
    return identifier(kind, v['inline']) if v['inline'] else v['reference'][0]['object_id']


def chunk(ref, index, raw):
    validate_manifest(ref)
    r.require(type(index) is int and 0 <= index < len(ref['chunk_hashes']), 'chunk-index')
    expected = min(CHUNK, ref['byte_length']-index*CHUNK)
    r.require(len(raw) == expected, 'chunk-length')
    r.require(r.digest('object-chunk', ref['object_id']+bytes([index])+raw) == ref['chunk_hashes'][index], 'chunk-hash')


def resolve(v, kind, fetch=None):
    validate_value(v, kind)
    if v['inline']:
        return v['inline']
    r.require(fetch is not None, 'object-unavailable')
    ref = v['reference'][0]
    # Caller applies aggregate/principal budgets before invoking this resolver.
    parts = []
    for index in range(len(ref['chunk_hashes'])):
        part = fetch(ref, index)
        chunk(ref, index, part)
        parts.append(part)
    raw = b''.join(parts)
    r.require(identifier(kind, raw) == ref['object_id'], 'object-hash')
    return raw


class Receiver:
    """One principal's bounded partial-object state; application auth is external."""
    def __init__(self, budget=67108864):
        r.require(0 < budget <= 67108864, 'transfer-budget')
        self.budget, self.reserved, self.pending = budget, 0, {}

    def put(self, ref, index, raw):
        chunk(ref, index, raw)
        mid = r.object_id('object_ref', ref)
        if mid not in self.pending:
            r.require(len(self.pending) < 4 and ref['byte_length'] <= self.budget-self.reserved, 'transfer-budget')
            self.pending[mid] = (ref, {})
            self.reserved += ref['byte_length']
        parts = self.pending[mid][1]
        r.require(index not in parts or parts[index] == raw, 'chunk-conflict')
        parts[index] = raw  # Exact retransmission is idempotent, not another chunk.
        return mid

    def finish(self, mid):
        r.require(mid in self.pending, 'object-unavailable')
        ref, parts = self.pending[mid]
        r.require(len(parts) == len(ref['chunk_hashes']), 'chunks-missing')
        out = resolve(dict(kind=ref['kind'], inline=b'', reference=[ref]), ref['kind'], lambda _, i: parts[i])
        self.drop(mid)
        return out

    def drop(self, mid):
        ref, _ = self.pending.pop(mid)
        self.reserved -= ref['byte_length']


def tl_wrap(tag, raw, kind):
    return r.tl_frame(tag, r.encode('object_value', value(raw, kind)))


def tl_unwrap(tag, frame, kind, fetch=None):
    return resolve(r.decode('object_value', r.tl_unframe(tag, frame)), kind, fetch)
