"""Strict thin transport and semantic correlation oracle; no network service."""
import json
import re
import reference as r

ZERO = bytes(32)
METHODS = r.SCHEMA['methods']
MAX_BINARY = r.SCHEMA['limits']['api_binary_bytes']
MAX_JSON = r.SCHEMA['limits']['transport_bytes']


def strict_json(raw):
    r.require(type(raw) is bytes and len(raw) <= MAX_JSON, 'transport-bound')
    def pairs(items):
        result = {}
        for k, v in items:
            r.require(k not in result, 'duplicate-json-key')
            result[k] = v
        return result
    def reject(_):
        raise r.Refusal('json-number')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_int=reject, parse_float=reject, parse_constant=reject)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise r.Refusal('json-syntax') from exc


def unhex(value, limit, width=None):
    r.require(type(value) is str and len(value) <= 2*limit
              and re.fullmatch(r'(?:[0-9a-f]{2})*', value) is not None, 'hex')
    raw = bytes.fromhex(value)
    r.require(width is None or len(raw) == width, 'hex-width')
    return raw


def request_id(method, request):
    r.require(str(method) in METHODS, 'method')
    if method == 1:
        return ZERO
    if method in (5, 6):
        return request['request_id']
    return r.digest('api-request', bytes([method]) + r.encode(METHODS[str(method)]['request'], request))


def decode_transport(raw, method, response=False, expected_id=None):
    r.require(str(method) in METHODS, 'method')
    obj = strict_json(raw)
    required = {'api_version', 'request_id', 'result', 'error'} if response else {'api_version', 'request_id', 'request'}
    r.require(type(obj) is dict and set(obj) == required and obj['api_version'] == '1', 'transport-fields')
    rid = unhex(obj['request_id'], 32, 32)
    if expected_id is not None:
        r.require(rid == expected_id, 'response-correlation')
    if response:
        r.require((obj['result'] is None) != (obj['error'] is None), 'result-or-error')
        is_error = obj['error'] is not None
        kind = 'error' if is_error else METHODS[str(method)]['result']
        value = r.decode(kind, unhex(obj['error'] if is_error else obj['result'], MAX_BINARY))
        if is_error:
            validate_error(value, method, rid)
        return rid, kind, value
    value = r.decode(METHODS[str(method)]['request'], unhex(obj['request'], MAX_BINARY))
    r.require(rid == request_id(method, value), 'request-correlation')
    validate_request(method, value)
    return rid, value


def encode_transport(method, value, response=False, rid=None, error=False):
    kind = 'error' if error else METHODS[str(method)]['result' if response else 'request']
    raw = r.encode(kind, value)
    r.require(len(raw) <= MAX_BINARY, 'api-binary-bound')
    if not response:
        rid = request_id(method, value)
    r.require(type(rid) is bytes and len(rid) == 32, 'request-id')
    obj = dict(api_version='1', request_id=rid.hex())
    if response:
        obj.update(result=None if error else raw.hex(), error=raw.hex() if error else None)
    else:
        obj['request'] = raw.hex()
    encoded = json.dumps(obj, separators=(',', ':')).encode()
    r.require(len(encoded) <= MAX_JSON, 'transport-bound')
    return encoded


def validate_error(error, method, rid):
    r.require(error['request_id'] == rid and error['method'] == method, 'error-correlation')
    r.require(1 <= error['code'] <= 14 and error['request_state'] in (0, 1, 2, 3, 4), 'error-code')
    # UNKNOWN=4 is error-only; never invent ABSENT after an unparseable request.
    retry = int(method in (1, 2, 6, 8, 9, 10, 11, 12, 13) and error['code'] in (10, 11, 12))
    r.require(error['retryable'] == retry, 'error-retry')
    try:
        error['message'].decode('utf-8')
    except UnicodeError as exc:
        raise r.Refusal('error-message') from exc


def validate_anchor(anchor):
    r.encode('anchor', anchor)
    r.require(anchor['seqno'] < (1 << 32)-1 and all(anchor[x] != ZERO for x in ('root', 'file', 'state')), 'anchor')


def query_id(anchor, limit):
    return r.digest('registry-query', r.encode('anchor', anchor) + bytes([limit]))


def validate_request(method, req):
    if 'anchor' in req:
        validate_anchor(req['anchor'])
    if method == 3:
        r.require(req['preparation_id'] != ZERO and req['identity'] != ZERO
                  and 1 <= req['role'] <= 5 and req['suite'] > 0 and req['parameters'] > 0
                  and 0 < req['epoch'] < (1 << 64)-1 and req['valid_from'] < req['valid_until'], 'preparation')
        r.require(req['mode'] in (0, 1) and (req['provider_handle'] == ZERO) == (req['mode'] == 0), 'preparation-mode')
    if method == 5:
        env = r.decode('envelope', req['envelope_template'])
        rows = env['record']['components']
        profiles = [(x['suite'], x['parameters']) for x in rows]
        r.require(1 <= len(rows) <= 2 and profiles == sorted(set(profiles))
                  and len(req['key_handles']) == len(rows) and len(set(req['key_handles'])) == len(rows)
                  and ZERO not in req['key_handles'] and all(x['signature'] == b'' for x in rows), 'sign-template')
        r.validate_payload(env['duty'], env['payload'])
        r.require(req['request_id'] == r.digest('sign-request', r.statement(env['duty'], env['record'])), 'sign-request-id')
    if method == 10:
        r.require(1 <= req['limit'] <= 128, 'page-limit')
        if req['cursor']:
            cursor = req['cursor'][0]
            r.require(cursor['anchor'] == req['anchor'] and cursor['query_id'] == query_id(req['anchor'], req['limit'])
                      and cursor['last_identity'] != ZERO, 'cursor-binding')
    if method in (4, 7):
        op = req['update']['operation']
        r.require(op in ((1, 2) if method == 4 else (3, 7)), 'endpoint-operation')
        if method == 4:
            r.require(req['update']['new_key'] == r.encode('key', req['key']) and req['handle'] != ZERO, 'stage-key')
            r.require(not req['authorizations']['possession'], 'stage-pop-output')
        elif op == 3:
            r.require(req['key_id'] == req['update']['old_key'], 'retire-key')
        r.require(not req['authorizations']['governance'], 'identity-not-governance')
    if method == 13:
        cert = r.decode('certificate', req['certificate'])
        for name, kind in (('committee', 5), ('policy', 2)):
            proof = req[name]
            r.require(proof['anchor'] == req['anchor'] and proof['kind'] == kind
                      and proof['object_id'] == cert['duty'][name], 'verify-request-context')
    if 'fence' in req:
        r.require(req['fence'] > 0, 'fence')


def verify_proof(proof, anchor, kind, object_id, verifier):
    r.encode('proofref', proof)
    r.require(proof['anchor'] == anchor and proof['kind'] == kind and proof['object_id'] == object_id, 'proof-binding')
    r.require(bool(proof['proof']) and proof['proof_hash'] == r.digest('proof', proof['proof']), 'proof-hash')
    r.require(verifier(proof), 'proof-authentication')


def verify_permit(permit, expected, public_keys, verifier, current_mc=None):
    r.encode('permit', permit)
    body = permit['body']
    r.require(set(expected) == set(body) - {'issuer'}, 'permit-expectations')
    r.require(all(body[n] == value for n, value in expected.items()), 'permit-context')
    r.require(body['anchor']['seqno'] <= body['expires_mc'] < (1 << 32)-1
              and body['expires_mc'] - body['anchor']['seqno'] <= 128, 'permit-expiry')
    r.require(current_mc is not None and body['anchor']['seqno'] <= current_mc <= body['expires_mc'], 'permit-current-coordinate')
    r.require(body['issuer'] in public_keys and len(permit['signature']) == 64, 'permit-issuer')
    r.require(body['issuer'] == r.digest('service-key', public_keys[body['issuer']]), 'permit-issuer-id')
    r.require(verifier.verify(public_keys[body['issuer']], r.encode('permit_body', body), permit['signature']), 'permit-signature')


def verify_receipt(receipt, expected, public_keys, verifier):
    r.encode('receipt', receipt)
    body = receipt['body']
    r.require(set(expected) == set(body) - {'issuer'}, 'receipt-expectations')
    r.require(all(body[n] == value for n, value in expected.items()), 'receipt-binding')
    r.require(body['journal_sequence'] > 0 and body['fence'] > 0 and body['state'] in (1, 2, 3), 'receipt-state')
    r.require(body['issuer'] in public_keys and len(receipt['signature']) == 64, 'receipt-issuer')
    r.require(body['issuer'] == r.digest('service-key', public_keys[body['issuer']]), 'receipt-issuer-id')
    r.require(verifier.verify(public_keys[body['issuer']], r.encode('receipt_body', body), receipt['signature']), 'receipt-signature')


def validate_request_state(state, rid):
    r.encode('request_state', state)
    r.require(state['request_id'] == rid, 'state-correlation')
    code = state['state']
    r.require(code in (0, 1, 2, 3), 'state-code')
    if code == 0:
        r.require(state['statement_id'] == ZERO and state['fence'] == 0 and not state['result'] and not state['receipt'], 'absent-shape')
    elif code == 2:
        r.require(len(state['result']) == 1 and not state['receipt'], 'complete-shape')
        result = state['result'][0]
        r.require(result['request_id'] == rid and result['statement_id'] == state['statement_id'] and result['fence'] == state['fence'], 'state-result')
    else:
        r.require(not state['result'] and len(state['receipt']) == 1
                  and state['receipt'][0]['body']['state'] == code, 'pending-shape')
    if code in (1, 3):
        body = state['receipt'][0]['body']
        r.require(body['request_id'] == rid and body['method'] == 5
                  and body['subject'] == state['statement_id'] and body['fence'] == state['fence']
                  and body['result_hash'] == ZERO, 'state-receipt-binding')
    if code != 0:
        r.require(state['statement_id'] != ZERO and state['fence'] > 0, 'known-state')


def validate_response(method, req, result):
    """Structural correlation before trusted proof/receipt verification."""
    r.encode(METHODS[str(method)]['result'], result)
    rid = request_id(method, req)
    if method == 1:
        r.require(all(result[n] in (0, 1) for n in ('persistent_journal', 'fencing', 'stateful'))
                  and 0 < result['max_request'] <= MAX_BINARY and 0 < result['max_result'] <= MAX_BINARY, 'capability-bounds')
        installed = [(p['suite'], p['parameters']) for p in result['installed']]
        admitted = [(p['suite'], p['parameters']) for p in result['admitted']]
        r.require(installed == sorted(set(installed)) and admitted == sorted(set(admitted))
                  and set(admitted) <= set(installed), 'capability-profiles')
    if method in (2, 11):
        key = result if method == 2 else result['key']
        r.require(r.object_id('key', key) == req['key_id'], 'response-key')
    if method == 3:
        key = result['prepared']['key']
        r.require(all(key[n] == req[n] for n in ('identity', 'role', 'suite', 'parameters', 'epoch', 'valid_from', 'valid_until'))
                  and result['prepared']['handle'] != ZERO, 'prepared-binding')
    if method == 4:
        r.require(result['key'] == req['key'] and result['possession']['key'] == r.keyref(req['key'])
                  and result['possession']['update_id'] == r.object_id('update', req['update']), 'staged-binding')
    if method == 5:
        template = r.decode('envelope', req['envelope_template'])
        statement = r.statement(template['duty'], template['record'])
        r.require(result['request_id'] == rid and result['statement_id'] == r.digest('statement', statement)
                  and result['fence'] == req['fence'] and r.statement(template['duty'], result['record']) == statement, 'sign-result-binding')
        r.require(all(len(x['signature']) > 0 for x in result['record']['components']), 'sign-result-signatures')
        r.require(all(len(x['signature']) == 64 for x in result['record']['components']
                      if (x['suite'], x['parameters']) == (1, 1)), 'sign-result-c0-size')
    if method == 6:
        validate_request_state(result, rid)
    if method == 7:
        r.require(result['key_id'] == req['key_id'] and result['update_id'] == r.object_id('update', req['update']), 'retirement-binding')
    if method >= 8:
        r.require(result['anchor'] == req['anchor'], 'response-anchor')
    if method == 8:
        r.require(result['can_parse'] in (0, 1) and result['can_verify'] in (0, 1)
                  and result['can_verify'] <= result['can_parse'], 'profile-flags')
        for field in ('installed', 'active'):
            profiles = [(x['suite'], x['parameters']) for x in result[field]]
            r.require(profiles == sorted(set(profiles)) and all(a > 0 and b > 0 for a,b in profiles), 'profile-suites')
    if method == 9:
        r.require(r.object_id('policy', result['policy']) == req['policy_id'], 'response-policy')
    if method == 10:
        ids = [x['identity'] for x in result['identities']]
        last = req['cursor'][0]['last_identity'] if req['cursor'] else ZERO
        r.require(len(ids) <= req['limit'] and ids == sorted(set(ids)) and all(i > last for i in ids), 'page-order')
        r.require(result['query_id'] == query_id(req['anchor'], req['limit']), 'page-query')
        if result['cursor']:
            c = result['cursor'][0]
            r.require(bool(ids) and c['last_identity'] == ids[-1] and c['anchor'] == req['anchor']
                      and c['query_id'] == result['query_id'], 'page-cursor')
    if method == 12:
        r.require(result['era'] == 1 and r.digest('certificate', result['certificate']) == req['certificate_id'], 'certificate-era')
        cert = r.decode('certificate', result['certificate'])
        r.require(result['committee']['object_id'] == cert['duty']['committee']
                  and result['policy']['object_id'] == cert['duty']['policy']
                  and result['committee']['anchor'] == req['anchor'] and result['policy']['anchor'] == req['anchor'], 'certificate-proof-binding')
    if method == 13:
        cert = r.decode('certificate', req['certificate'])
        r.require(result['certificate_id'] == r.digest('certificate', req['certificate'])
                  and result['policy'] == cert['duty']['policy'] and result['committee'] == cert['duty']['committee']
                  and result['duty'] == r.object_id('duty', cert['duty']), 'verified-binding')
        signers = [x['identity'] for x in cert['records']]
        r.require(bool(signers) and signers == sorted(set(signers)) and ZERO not in signers, 'verified-signer-order')
        r.require(result['signers'] == signers and 0 < result['weight'] <= r.MAX_WEIGHT, 'verified-signers')


def result_hash(method, result):
    kind = METHODS[str(method)]['result'] + '_body'
    r.require(kind in r.SCHEMAS, 'receipt-method')
    core = {k: v for k, v in result.items() if k != 'receipt'}
    return r.digest('api-result', bytes([method]) + r.encode(kind, core))


def verify_result_receipt(method, req, result, audience, issuer_keys, verifier):
    validate_response(method, req, result)
    body = result['receipt']['body']
    subject = result['statement_id'] if method == 5 else r.digest('api-subject', r.encode(METHODS[str(method)]['request'], req))
    context_id = r.object_id('permit', req['permit']) if 'permit' in req else ZERO
    expected = dict(audience=audience, request_id=request_id(method, req), method=method,
                    subject=subject, result_hash=result_hash(method, result), journal_sequence=body['journal_sequence'],
                    fence=req['fence'], state=2, context_id=context_id)
    verify_receipt(result['receipt'], expected, issuer_keys, verifier)


def registry_page_id(req, result):
    start = req['cursor'][0]['last_identity'] if req['cursor'] else ZERO
    return r.digest('registry-page', result['query_id'] + start
                    + r.encode('l8/128/identity', result['identities']) + r.encode('l8/1/cursor', result['cursor']))


def verify_client_proofs(method, req, result, verifier):
    """Binding plus a required native state/range proof callback, never hash-only."""
    validate_response(method, req, result)
    if method in (8, 9, 10, 11):
        kind = {8: 6, 9: 2, 10: 3, 11: 4}[method]
        target = {8: r.object_id('profile_state', {k:result[k] for k in ('interface_digest','policy','active')}) if method == 8 else None, 9: req.get('policy_id'),
                  10: registry_page_id(req, result) if method == 10 else None, 11: req.get('key_id')}[method]
        verify_proof(result['proof'], req['anchor'], kind, target, verifier)
    elif method == 12:
        cert = r.decode('certificate', result['certificate'])
        verify_proof(result['committee'], req['anchor'], 5, cert['duty']['committee'], verifier)
        verify_proof(result['policy'], req['anchor'], 2, cert['duty']['policy'], verifier)
    else:
        raise r.Refusal('client-proof-method')


def observe_request_state(previous, current, rid):
    """Check authenticated polling observations before replacing local history.

    Callers verify each state's receipt and issuer first. This comparison neither
    authenticates a receipt nor proves a service's durable storage. It detects a
    weaker response that must not overwrite an already observed safety result.
    """
    validate_request_state(current, rid)
    if previous is None:
        return
    validate_request_state(previous, rid)
    if previous['state'] in (2, 3):
        r.require(previous == current, 'terminal-state-regression')
    elif previous['state'] == 1:
        r.require(current['state'] != 0, 'reserved-state-regression')
        r.require(current['statement_id'] == previous['statement_id']
                  and current['fence'] == previous['fence'], 'reserved-state-binding')
