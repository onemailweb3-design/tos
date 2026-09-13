"""Executable lifecycle, transport and authority-boundary specification tests."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
import api
import lifecycle as lc
import reference as r
import vectors
from ed25519_oracle import Verifier

h = vectors.h
ZERO = bytes(32)
HERE = Path(__file__).resolve().parent


def key(role=1, epoch=1, start=0):
    public, _ = vectors.sign(h(1), b'fixture')
    return dict(identity=h(11), role=role, suite=1, parameters=1, epoch=epoch,
                valid_from=start, valid_until=1000, public_key=public, capacity_domain=ZERO, capacity_limit=0)


def initial():
    keys = [key(role) for role in range(1, 6)]
    archive = {r.object_id('key', k): k for k in keys}
    state = dict(identity=h(11), stake_id=h(21), owner_workchain=-1, owner_address=h(22), next_nonce=1,
                 previous=ZERO, active=[dict(role=k['role'], key=r.keyref(k)) for k in keys], pending=[])
    return state, archive


def update(state, archive, op=2, effective=200, role=1, nonce=None):
    old = next((x['key']['key_id'] for x in state['active'] if x['role'] == role), ZERO)
    return dict(operation=op, identity=state['identity'], nonce=state['next_nonce'] if nonce is None else nonce,
                previous=r.object_id('identity', state), effective_from=effective, old_key=ZERO if op in (1, 7) else old,
                new_key=r.encode('key', key(role, 2, effective)) if op in (1, 2) else b'', new_policy=b'', operation_data=b'')


def proof(kind=1, object_id=None):
    raw = b'authenticated-proof-fixture'
    return dict(anchor=anchor(), kind=kind, object_id=h(5) if object_id is None else object_id,
                proof_hash=r.digest('proof', raw), proof=raw)


def anchor():
    return dict(seqno=100, root=h(51), file=h(52), state=h(53))


def evidence(u, state):
    uid = r.object_id('update', u)
    owner = dict(update_id=uid, stake_id=state['stake_id'], owner_workchain=state['owner_workchain'],
                 owner_address=state['owner_address'], proof=proof())
    possession = dict(update_id=uid, key=r.keyref(r.decode('key', u['new_key'])), signature=h(8)*2) if u['new_key'] else None
    return dict(owner=[owner] if u['operation'] in (1, 2) else [], possession=[possession] if possession else [],
                administration=[dict(update_id=uid, identity=state['identity'], certificate=b'authenticated-admin-fixture')], governance=[])


VERIFIERS = {n: lambda *args: True for n in ('owner', 'possession', 'administration', 'governance')}


def apply(state, archive, u, at=100, auth=None, verifiers=None):
    return lc.apply(state, archive, u, evidence(u, state) if auth is None else auth, at,
                    VERIFIERS if verifiers is None else verifiers, lambda k: Verifier().admit(k['public_key']) and (k['suite'], k['parameters']) == (1, 1))


def shape(t):
    if t in r.FORMATS:
        return 1
    if t == 'h':
        return h(1)
    if t.startswith('b'):
        return b'\x01'
    if t.startswith('l'):
        return [shape(t.split('/')[-1])]
    return {n: shape(k) for n, k in r.fields(t)}



def wire_shape(t, path='root'):
    material = hashlib.sha256(path.encode()).digest()
    if t in r.FORMATS:
        return int.from_bytes(material[:1], 'big')
    if t == 'h':
        return material
    if t.startswith('b'):
        return material[:min(7, int(t[1:]))]
    if t.startswith('l'):
        return [wire_shape(t.split('/')[-1], path+'/0')]
    return {n: wire_shape(k, path+'/'+n) for n,k in r.fields(t)}


def golden():
    # Structural fixtures intentionally include non-authoritative values; actual
    # admission/authorization scenarios are executed separately below.
    objects = {n: r.encode(n, wire_shape(n, n)).hex() for n in r.SCHEMAS}
    s, a = initial(); u = update(s, a); staged, a = apply(s, a, u)
    history = {str(n): r.encode('identity', lc.advance(staged, a, n)).hex() for n in (199, 200, 201)}
    return dict(scope='Ordered binary structural vectors plus lifecycle state snapshots; proof fixture bytes are not native Merkle evidence',
                objects=objects, lifecycle=history, negatives=[
                    dict(kind='capabilities_request',hex='5641713100020000',error='version'),
                    dict(kind='capabilities_request',hex='5641713100010001',error='flags'),
                    dict(kind='capabilities_request',hex='564171310001000000',error='trailing'),
                    dict(kind='public_request',hex='5641713200010000',error='truncated'),
                    dict(kind='authorizations',hex='564141310001000002',error='list-bound')])


class LifecycleTests(unittest.TestCase):
    def test_before_exact_after_replay_and_old_session(self):
        s, a = initial(); old_session = lc.snapshot(s, a, 100, [(1, 1, 1)])
        staged, a = apply(s, a, update(s, a))
        self.assertEqual(lc.snapshot(staged, a, 199, [(1, 1, 1)])[0]['epoch'], 1)
        for at in (200, 201):
            self.assertEqual(lc.snapshot(staged, a, at, [(1, 1, 1)])[0]['epoch'], 2)
        reloaded = r.decode('identity', r.encode('identity', staged))
        self.assertEqual(lc.advance(reloaded, a, 200), lc.advance(staged, a, 200))
        self.assertEqual(old_session[0]['epoch'], 1)
        first = lc.snapshot(s, a, 100, [(1, 1, 1)])
        archive_key = a[r.object_id('key', first[0])]
        saved_epoch = archive_key['epoch']; archive_key['epoch'] = 77
        self.assertEqual(first[0]['epoch'], 1)
        archive_key['epoch'] = saved_epoch
        done = lc.advance(staged, a, 200)
        self.assertEqual(lc.advance(done, a, 201), done)
        self.assertEqual(done['next_nonce'], staged['next_nonce'])

    def test_unrelated_change_does_not_invalidate_accepted_schedule(self):
        s, a = initial(); staged, a = apply(s, a, update(s, a))
        other, a = apply(staged, a, update(staged, a, role=2, effective=210), 150)
        self.assertNotEqual(other['previous'], staged['previous'])
        self.assertEqual(lc.snapshot(other, a, 200, [(1, 1, 1)])[0]['epoch'], 2)
        self.assertEqual(lc.snapshot(other, a, 210, [(2, 1, 1)])[0]['epoch'], 2)

    def test_explicit_cancel_and_conflict_no_silent_replace(self):
        s, a = initial(); staged, a = apply(s, a, update(s, a))
        conflict = update(staged, a, effective=300)
        next_key = r.decode('key', conflict['new_key']); next_key['epoch'] = 3
        conflict['new_key'] = r.encode('key', next_key)
        with self.assertRaisesRegex(r.Refusal, 'pending-conflict'):
            apply(staged, a, conflict)
        cancel = update(staged, a, op=7, effective=0)
        cancel['operation_data'] = r.object_id('transition', staged['pending'][0])
        canceled, saved = apply(staged, a, cancel, 199)
        self.assertEqual(canceled['pending'], [])
        self.assertEqual(saved, a)
        self.assertEqual(lc.snapshot(canceled, saved, 200, [(1, 1, 1)])[0]['epoch'], 1)
        replacement = update(canceled, saved, effective=300)
        with self.assertRaisesRegex(r.Refusal, 'epoch'):
            apply(canceled, saved, replacement, 199)
        new = r.decode('key', replacement['new_key']); new['epoch'] = 3
        replacement['new_key'] = r.encode('key', new)
        replaced, _ = apply(canceled, saved, replacement, 199)
        self.assertEqual(len(replaced['pending']), 1)
        with self.assertRaisesRegex(r.Refusal, 'predecessor'):
            apply(staged, a, cancel, 200)
        cancel['previous'] = r.object_id('identity', lc.advance(staged, a, 200))
        with self.assertRaisesRegex(r.Refusal, 'cancel-target'):
            apply(staged, a, cancel, 200)
        cancel['operation_data'] = h(99)
        cancel['previous'] = r.object_id('identity', staged)
        with self.assertRaisesRegex(r.Refusal, 'cancel-target'):
            apply(staged, a, cancel, 199)

    def test_retire_immediate_scheduled_and_key_validity(self):
        s, a = initial()
        retired, a = apply(s, a, update(s, a, op=3))
        self.assertEqual(len(lc.snapshot(retired, a, 199, [(1, 1, 1)])), 1)
        with self.assertRaisesRegex(r.Refusal, 'snapshot-missing'):
            lc.snapshot(retired, a, 200, [(1, 1, 1)])
        immediate, _ = apply(s, a, update(s, a, op=3, effective=0), 123)
        self.assertEqual(len(immediate['active']), 4)
        with self.assertRaisesRegex(r.Refusal, 'snapshot-validity'):
            lc.snapshot(s, a, 1000, [(1, 1, 1)])

    def test_nonce_predecessor_boundaries_and_atomic_refusal(self):
        s, a = initial(); original = copy.deepcopy((s, a))
        for field, val, code in [('nonce', 0, 'nonce'), ('nonce', (1<<64)-1, 'nonce'),
                                  ('previous', ZERO, 'predecessor'), ('effective_from', 99, 'effective-coordinate'),
                                  ('effective_from', 100+lc.MAX_DELAY+1, 'effective-coordinate'),
                                  ('effective_from', (1<<32)-1, 'effective-coordinate'), ('old_key', h(99), 'old-key')]:
            u = update(s, a); u[field] = val
            with self.subTest(field=field, val=val), self.assertRaisesRegex(r.Refusal, code):
                apply(s, a, u)
        u = update(s, a, nonce=5)
        result, _ = apply(s, a, u)
        self.assertEqual(result['next_nonce'], 6)
        self.assertEqual((s, a), original)
        for field, value in [('valid_from', 199), ('valid_until', 200)]:
            u = update(s, a); new = r.decode('key', u['new_key']); new[field] = value; u['new_key'] = r.encode('key', new)
            with self.assertRaisesRegex(r.Refusal, 'new-key-validity'):
                apply(s, a, u)

    def test_four_authorities_cannot_substitute(self):
        s, a = initial(); u = update(s, a)
        for name in ('owner', 'possession', 'administration'):
            auth = evidence(u, s); auth[name] = []
            with self.subTest(missing=name), self.assertRaisesRegex(r.Refusal, 'authority-shape'):
                apply(s, a, u, auth=auth)
            deny = dict(VERIFIERS); deny[name] = lambda *args: False
            with self.subTest(denied=name), self.assertRaisesRegex(r.Refusal, 'authority-'+name):
                apply(s, a, u, verifiers=deny)
        auth = evidence(u, s)
        auth['governance'] = [dict(update_id=r.object_id('update', u), committee=h(5), certificate=b'proof')]
        with self.assertRaisesRegex(r.Refusal, 'authority-shape'):
            apply(s, a, u, auth=auth)
        auth = evidence(u, s); auth['administration'][0]['update_id'] = h(9)
        with self.assertRaisesRegex(r.Refusal, 'authority-update'):
            apply(s, a, u, auth=auth)

    def test_authenticated_pending_structure(self):
        s, a = initial(); staged, a = apply(s, a, update(s, a))
        for field, val, code in [('old_key', h(9), 'pending-old'), ('effective_from', 99, 'pending-coordinate'),
                                 ('new_key', h(9), 'pending-key'), ('operation', 7, 'pending-operation')]:
            bad = copy.deepcopy(staged); bad['pending'][0][field] = val
            with self.subTest(field=field), self.assertRaisesRegex(r.Refusal, code):
                lc.advance(bad, a, 200)
        bad = copy.deepcopy(staged); bad['pending'] *= 2
        with self.assertRaisesRegex(r.Refusal, 'state-order'):
            lc.advance(bad, a, 200)
        bad['pending'] *= 6
        with self.assertRaisesRegex(r.Refusal, 'list-bound'):
            lc.advance(bad, a, 200)

    def test_register_after_retirement_uses_historical_epoch(self):
        s, a = initial(); retired, a = apply(s, a, update(s, a, op=3, effective=0))
        registered, a = apply(retired, a, update(retired, a, op=1, effective=150))
        self.assertEqual(lc.snapshot(registered, a, 150, [(1, 1, 1)])[0]['epoch'], 2)


class ApiTests(unittest.TestCase):
    def test_all_ordered_types_frozen_and_negative_headers(self):
        frozen = json.loads((HERE/'lifecycle-api-golden.json').read_text())
        self.assertEqual(golden(), frozen)
        for negative in frozen['negatives']:
            with self.subTest(negative=negative), self.assertRaisesRegex(r.Refusal,negative['error']):
                r.decode(negative['kind'],bytes.fromhex(negative['hex']))
        for name, raw in frozen['objects'].items():
            self.assertEqual(r.decode(name, bytes.fromhex(raw)),wire_shape(name,name))
        for name, definition in r.SCHEMA['types'].items():
            obj = shape(name); wire = r.encode(name, obj)
            with self.subTest(name=name):
                self.assertEqual(r.decode(name, wire), obj)
                with self.assertRaisesRegex(r.Refusal, 'trailing'):
                    r.decode(name, wire+b'\0')
                if definition['tag']:
                    for offset, code in ((5, 'version'), (7, 'flags')):
                        bad = bytearray(wire); bad[offset] = 2
                        with self.assertRaisesRegex(r.Refusal, code):
                            r.decode(name, bytes(bad))

    def test_endpoint_inventory_and_transport_responses(self):
        self.assertEqual(len(api.METHODS), 13)
        for method, definition in api.METHODS.items():
            method = int(method); result = shape(definition['result']); rid = h(4)
            encoded = api.encode_transport(method, result, response=True, rid=rid)
            self.assertEqual(api.decode_transport(encoded, method, response=True, expected_id=rid)[2], result)
            with self.assertRaisesRegex(r.Refusal, 'response-correlation'):
                api.decode_transport(encoded, method, response=True, expected_id=h(5))
            for code in range(1, 15):
                retry = int(method in (1,2,6,8,9,10,11,12,13) and code in (10,11,12))
                error = dict(request_id=rid, method=method, code=code, retryable=retry, request_state=4, message=b'diagnostic')
                encoded = api.encode_transport(method, error, response=True, rid=rid, error=True)
                self.assertEqual(api.decode_transport(encoded, method, response=True, expected_id=rid)[2], error)

    def test_strict_json_duplicate_keys_before_mapping(self):
        for raw in (b'{"a":"x","a":"y"}', b'{"outer":{"a":"x","\\u0061":"y"}}'):
            with self.assertRaisesRegex(r.Refusal, 'duplicate-json-key'):
                api.strict_json(raw)
        for raw in (b'1', b'1.2', b'NaN', b'Infinity'):
            with self.assertRaisesRegex(r.Refusal, 'json-number'):
                api.strict_json(raw)
        with self.assertRaisesRegex(r.Refusal, 'json-syntax'):
            api.strict_json(b'"\xff"')
        for value in ('A0', '0', ' 00', '0x00'):
            with self.assertRaisesRegex(r.Refusal, 'hex'):
                api.unhex(value, 10)
        good = api.encode_transport(2, {'key_id': h(1)})
        self.assertEqual(api.decode_transport(good, 2)[1], {'key_id': h(1)})
        for field, val in [('api_version', '01'), ('extra', 'x'), ('request_id', h(2).hex())]:
            obj = json.loads(good); obj[field] = val
            with self.assertRaisesRegex(r.Refusal, 'transport-fields|request-correlation'):
                api.decode_transport(json.dumps(obj).encode(), 2)
        with self.assertRaisesRegex(r.Refusal, 'transport-bound'):
            api.strict_json(b' '*(api.MAX_JSON+1))
        with self.assertRaisesRegex(r.Refusal, 'hex'):
            api.unhex('00'*(api.MAX_BINARY+1), api.MAX_BINARY)

    def test_sign_request_and_result_correlation(self):
        fixtures = vectors.build(); env = r.decode('envelope', bytes.fromhex(fixtures['cases'][0]['envelope']))
        signed = copy.deepcopy(env['record'])
        for c in env['record']['components']:
            c['signature'] = b''
        statement = r.statement(env['duty'], env['record'])
        req = dict(request_id=r.digest('sign-request', statement), key_handles=[h(1)],
                   envelope_template=r.encode('envelope', env), permit=shape('permit'), fence=1)
        api.validate_request(5, req)
        result = dict(request_id=req['request_id'], statement_id=r.digest('statement', statement), record=signed, fence=1, receipt=shape('receipt'))
        api.validate_response(5, req, result)
        for field, value in [('request_id', h(2)), ('fence', 2), ('statement_id', h(2))]:
            bad = copy.deepcopy(result); bad[field] = value
            with self.assertRaisesRegex(r.Refusal, 'sign-result-binding'):
                api.validate_response(5, req, bad)
        bad = copy.deepcopy(req); bad['request_id'] = h(2)
        with self.assertRaisesRegex(r.Refusal, 'sign-request-id'):
            api.validate_request(5, bad)

    def test_request_state_variants(self):
        rid = h(1)
        absent = dict(request_id=rid, state=0, statement_id=ZERO, fence=0, result=[], receipt=[])
        api.validate_request_state(absent, rid)
        for field, val in [('statement_id', h(2)), ('fence', 1), ('result', [shape('sign_result')])]:
            bad = copy.deepcopy(absent); bad[field] = val
            with self.assertRaisesRegex(r.Refusal, 'absent-shape'):
                api.validate_request_state(bad, rid)
        for code in (1, 3):
            receipt = shape('receipt'); receipt['body'].update(state=code, method=5, subject=h(2), result_hash=ZERO)
            obj = dict(request_id=rid, state=code, statement_id=h(2), fence=1, result=[], receipt=[receipt])
            api.validate_request_state(obj, rid)
            obj['result'] = [shape('sign_result')]
            with self.assertRaisesRegex(r.Refusal, 'pending-shape'):
                api.validate_request_state(obj, rid)
        result = shape('sign_result')
        obj = dict(request_id=rid, state=2, statement_id=h(1), fence=1, result=[result], receipt=[])
        api.validate_request_state(obj, rid)
        obj['result'][0]['request_id'] = h(2)
        with self.assertRaisesRegex(r.Refusal, 'state-result'):
            api.validate_request_state(obj, rid)

    def test_cursor_snapshot_and_page_correlation(self):
        req = dict(anchor=anchor(), limit=2, cursor=[])
        s, _ = initial()
        result = dict(anchor=anchor(), query_id=api.query_id(anchor(), 2), identities=[s], cursor=[], proof=proof())
        api.validate_request(10, req); api.validate_response(10, req, result)
        cursor = dict(anchor=anchor(), query_id=result['query_id'], last_identity=s['identity'])
        req['cursor'] = [cursor]; api.validate_request(10, req)
        with self.assertRaisesRegex(r.Refusal, 'page-order'):
            api.validate_response(10, req, result)
        req['limit'] = 3
        with self.assertRaisesRegex(r.Refusal, 'cursor-binding'):
            api.validate_request(10, req)
        req['limit'] = 2; req['cursor'][0]['anchor']['state'] = h(99)
        with self.assertRaisesRegex(r.Refusal, 'cursor-binding'):
            api.validate_request(10, req)
        req['cursor'] = []; result['anchor']['file'] = h(9)
        with self.assertRaisesRegex(r.Refusal, 'response-anchor'):
            api.validate_response(10, req, result)

    def test_proof_reference_needs_authenticated_source(self):
        p = proof()
        api.verify_proof(p, anchor(), 1, h(5), lambda _: True)
        with self.assertRaisesRegex(r.Refusal, 'proof-authentication'):
            api.verify_proof(p, anchor(), 1, h(5), lambda _: False)
        for field, val, code in [('kind', 2, 'proof-binding'), ('object_id', h(9), 'proof-binding'), ('proof', b'x', 'proof-hash')]:
            bad = copy.deepcopy(p); bad[field] = val
            with self.assertRaisesRegex(r.Refusal, code):
                api.verify_proof(bad, anchor(), 1, h(5), lambda _: True)

    def test_permit_and_receipt_real_signatures_distinct_from_authority(self):
        public, _ = vectors.sign(h(1), b'fixture'); verifier = Verifier()
        for kind, verify in [('permit', api.verify_permit), ('receipt', api.verify_receipt)]:
            obj = shape(kind); body = obj['body']; issuer = r.digest('service-key', public); body['issuer'] = issuer
            options = {'current_mc': 100} if kind == 'permit' else {}
            if kind == 'permit':
                body['anchor'] = anchor(); body['expires_mc'] = 128
            wire = r.encode(kind+'_body', body)
            _, obj['signature'] = vectors.sign(h(1), wire)
            expected = {k: v for k, v in body.items() if k != 'issuer'}
            verify(obj, expected, {issuer: public}, verifier, **options)
            with self.assertRaisesRegex(r.Refusal, kind+'-issuer'):
                verify(obj, expected, {}, verifier, **options)
            bad = copy.deepcopy(expected); bad['audience'] = h(9)
            with self.assertRaisesRegex(r.Refusal, 'permit-context|receipt-binding'):
                verify(obj, bad, {issuer: public}, verifier, **options)
            obj['signature'] = h(3)*2
            with self.assertRaisesRegex(r.Refusal, kind+'-signature'):
                verify(obj, expected, {issuer: public}, verifier, **options)

    def test_all_endpoint_semantic_pairs_and_single_field_mutations(self):
        fixtures = vectors.build(); policy = r.decode('policy', bytes.fromhex(fixtures['policy']))
        cert = bytes.fromhex(fixtures['cases'][0]['certificate']); duty = r.decode('certificate', cert)['duty']
        state, archive = initial(); k = key(); kid = r.object_id('key', k); u = update(state, archive)
        prep = dict(preparation_id=h(9), identity=k['identity'], role=1, suite=1, parameters=1, epoch=1,
                    valid_from=0, valid_until=1000, mode=0, provider_handle=ZERO, fence=1)
        stage = dict(key=r.decode('key', u['new_key']), handle=h(1), update=u, authorizations=evidence(u, state), permit=shape('permit'), fence=1)
        stage['authorizations']['possession'] = []
        retire = update(state, archive, op=3)
        requests = {
            1: {}, 2: dict(key_id=kid), 3: prep, 4: stage,
            6: dict(request_id=h(9)),
            7: dict(key_id=kid, update=retire, authorizations=evidence(retire, state), permit=shape('permit'), fence=1),
            8: dict(anchor=anchor()), 9: dict(anchor=anchor(), policy_id=r.object_id('policy', policy)),
            10: dict(anchor=anchor(), limit=2, cursor=[]), 11: dict(anchor=anchor(), key_id=kid),
            12: dict(anchor=anchor(), certificate_id=r.digest('certificate', cert)),
            13: dict(anchor=anchor(), certificate=cert, committee=proof(5, duty['committee']), policy=proof(2, duty['policy']))}
        results = {
            1: dict(interface_digest=policy['interface_digest'], installed=[dict(suite=1,parameters=1)], admitted=[dict(suite=1,parameters=1)], max_request=api.MAX_BINARY, max_result=api.MAX_BINARY, persistent_journal=1, fencing=1, stateful=0),
            2: k, 3: dict(prepared=dict(key=k,handle=h(1)),receipt=shape('receipt')),
            4: dict(key=stage['key'], possession=evidence(u,state)['possession'][0], receipt=shape('receipt')),
            6: dict(request_id=h(9), state=0, statement_id=ZERO, fence=0, result=[], receipt=[]),
            7: dict(key_id=kid, update_id=r.object_id('update',retire), receipt=shape('receipt')),
            8: dict(anchor=anchor(), interface_digest=policy['interface_digest'], policy=r.object_id('policy',policy), installed=[dict(suite=1,parameters=1)], active=[dict(suite=1,parameters=1)], can_parse=1, can_verify=1, proof=proof(6,policy['interface_digest'])),
            9: dict(anchor=anchor(), policy=policy, proof=proof(2,r.object_id('policy',policy))),
            10: dict(anchor=anchor(), query_id=api.query_id(anchor(),2), identities=[state], cursor=[], proof=proof()),
            11: dict(anchor=anchor(), key=k, proof=proof(4,kid)),
            12: dict(anchor=anchor(), era=1, interface_digest=policy['interface_digest'], certificate=cert, committee=proof(5,duty['committee']), policy=proof(2,duty['policy'])),
            13: dict(anchor=anchor(), certificate_id=r.digest('certificate',cert), policy=duty['policy'], committee=duty['committee'], duty=r.object_id('duty',duty), signers=[h(11),h(12),h(13)],weight=3)}
        results[8]['proof'] = proof(6,r.object_id('profile_state',{k:results[8][k] for k in ('interface_digest','policy','active')}))
        results[10]['proof'] = proof(3, api.registry_page_id(requests[10],results[10]))
        # Method 5 is exercised using a real signed fixture by the sign test.
        for method, req in requests.items():
            with self.subTest(method=method):
                api.validate_request(method,req); api.validate_response(method,req,results[method])
                self.assertEqual(api.decode_transport(api.encode_transport(method,req),method)[1],req)
                if 8 <= method <= 12:
                    api.verify_client_proofs(method,req,results[method],lambda p: True)
                    with self.assertRaisesRegex(r.Refusal,'proof-authentication'):
                        api.verify_client_proofs(method,req,results[method],lambda p: False)
        bad=copy.deepcopy(results[3]);bad['prepared']['key']['epoch']=2
        with self.assertRaisesRegex(r.Refusal,'prepared-binding'):
            api.validate_response(3,prep,bad)
        bad=copy.deepcopy(results[4]);bad['possession']['update_id']=h(9)
        with self.assertRaisesRegex(r.Refusal,'staged-binding'):
            api.validate_response(4,stage,bad)
        bad=copy.deepcopy(results[7]);bad['update_id']=h(9)
        with self.assertRaisesRegex(r.Refusal,'retirement-binding'):
            api.validate_response(7,requests[7],bad)
        bad=copy.deepcopy(results[12]);bad['era']=0
        with self.assertRaisesRegex(r.Refusal,'certificate-era'):
            api.validate_response(12,requests[12],bad)
        bad=copy.deepcopy(results[13]);bad['committee']=h(9)
        with self.assertRaisesRegex(r.Refusal,'verified-binding'):
            api.validate_response(13,requests[13],bad)

    def test_complete_receipt_binds_exact_result_and_permit_expiry(self):
        k=key();req=dict(preparation_id=h(9),identity=k['identity'],role=1,suite=1,parameters=1,epoch=1,
                        valid_from=0,valid_until=1000,mode=0,provider_handle=ZERO,fence=1)
        result=dict(prepared=dict(key=k,handle=h(1)),receipt=shape('receipt'))
        public,_=vectors.sign(h(1),b'fixture');issuer=r.digest('service-key',public)
        body=dict(issuer=issuer,audience=h(8),request_id=api.request_id(3,req),method=3,
                  subject=r.digest('api-subject',r.encode('prepare_request',req)),result_hash=api.result_hash(3,result),
                  journal_sequence=1,fence=1,state=2,context_id=ZERO)
        _,signature=vectors.sign(h(1),r.encode('receipt_body',body))
        result['receipt']=dict(body=body,signature=signature)
        api.verify_result_receipt(3,req,result,h(8),{issuer:public},Verifier())
        result['prepared']['handle']=h(2)
        with self.assertRaisesRegex(r.Refusal,'receipt-binding'):
            api.verify_result_receipt(3,req,result,h(8),{issuer:public},Verifier())
        permit=shape('permit');permit['body'].update(issuer=issuer,anchor=anchor(),expires_mc=110)
        _,permit['signature']=vectors.sign(h(1),r.encode('permit_body',permit['body']))
        expected={k:v for k,v in permit['body'].items() if k!='issuer'}
        for at in (100,110):
            api.verify_permit(permit,expected,{issuer:public},Verifier(),at)
        for at in (99,111):
            with self.assertRaisesRegex(r.Refusal,'permit-current-coordinate'):
                api.verify_permit(permit,expected,{issuer:public},Verifier(),at)


if __name__ == '__main__':
    unittest.main()
