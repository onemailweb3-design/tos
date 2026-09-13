"""API admission and polling regressions; cryptographic/proof verification is separate."""
import copy
import unittest

import api
import transfer as tr
import reference as r
import vectors
from test_lifecycle_api import ZERO, h, shape, anchor, proof


class ApiGuardTests(unittest.TestCase):
    def test_c0_sign_result_requires_exact_signature_size(self):
        fixtures = vectors.build()
        env = r.decode('envelope', bytes.fromhex(fixtures['cases'][0]['envelope']))
        signed = copy.deepcopy(env['record'])
        for component in env['record']['components']:
            component['signature'] = b''
        statement = r.statement(env['duty'], env['record'])
        req = dict(request_id=r.digest('sign-request', statement), key_handles=[h(1)],
                   envelope_template=r.encode('envelope', env), permit=shape('permit'), fence=1)
        result = dict(request_id=req['request_id'], statement_id=r.digest('statement', statement),
                      record=signed, fence=1, receipt=shape('receipt'))
        api.validate_request(5, req)
        api.validate_response(5, req, result)
        for size in (1, 63, 65, 2420):
            bad = copy.deepcopy(result)
            bad['record']['components'][0]['signature'] = b'x'*size
            with self.subTest(size=size), self.assertRaisesRegex(r.Refusal, 'sign-result-c0-size'):
                api.validate_response(5, req, bad)

    def test_verified_summary_rejects_noncanonical_signers(self):
        fixtures = vectors.build()
        cert = r.decode('certificate', bytes.fromhex(fixtures['cases'][0]['certificate']))
        for mode in ('positive', 'duplicate', 'reversed', 'empty', 'zero'):
            changed = copy.deepcopy(cert)
            if mode == 'duplicate': changed['records'] = [changed['records'][0]]*2
            if mode == 'reversed': changed['records'].reverse()
            if mode == 'empty': changed['records'] = []
            if mode == 'zero': changed['records'][0]['identity'] = ZERO
            raw = r.encode('certificate', changed); duty = changed['duty']
            req = dict(anchor=anchor(), certificate=tr.value(raw, 4),
                       committee=proof(5, duty['committee']), policy=proof(2, duty['policy']))
            result = dict(anchor=anchor(), certificate_id=r.digest('certificate', raw),
                          policy=duty['policy'], committee=duty['committee'], duty=r.object_id('duty', duty),
                          signers=[row['identity'] for row in changed['records']], weight=3)
            if mode == 'positive':
                api.validate_response(13, req, result)
            else:
                with self.subTest(mode=mode), self.assertRaisesRegex(r.Refusal, 'verified-signer-order'):
                    api.validate_response(13, req, result)

    def test_verification_request_pins_both_context_proofs(self):
        fixtures = vectors.build(); raw = bytes.fromhex(fixtures['cases'][0]['certificate'])
        duty = r.decode('certificate', raw)['duty']
        req = dict(anchor=anchor(), certificate=tr.value(raw, 4),
                   committee=proof(5, duty['committee']), policy=proof(2, duty['policy']))
        api.validate_request(13, req)
        for name in ('committee', 'policy'):
            for field in ('anchor', 'kind', 'object_id'):
                bad = copy.deepcopy(req)
                if field == 'anchor': bad[name]['anchor']['state'] = h(99)
                elif field == 'kind': bad[name]['kind'] = 1
                else: bad[name]['object_id'] = h(99)
                with self.subTest(name=name, field=field), self.assertRaisesRegex(r.Refusal, 'verify-request-context'):
                    api.validate_request(13, bad)

    def test_polling_preserves_terminal_state_and_exact_result(self):
        rid = h(1)
        result = shape('sign_result')
        complete = dict(request_id=rid, state=2, statement_id=h(1), fence=1, result=[result], receipt=[])
        absent = dict(request_id=rid, state=0, statement_id=ZERO, fence=0, result=[], receipt=[])
        def pending(code):
            receipt = shape('receipt')
            receipt['body'].update(request_id=rid, method=5, subject=h(1), fence=1, state=code, result_hash=ZERO)
            return dict(request_id=rid, state=code, statement_id=h(1), fence=1, result=[], receipt=[receipt])
        reserved, burned = pending(1), pending(3)
        for old, new in ((None, absent), (absent, reserved), (reserved, complete),
                         (reserved, burned), (complete, copy.deepcopy(complete)), (burned, copy.deepcopy(burned))):
            api.observe_request_state(old, new, rid)
        for old in (complete, burned):
            for new in (absent, reserved, burned if old is complete else complete):
                with self.subTest(old=old['state'], new=new['state']), self.assertRaisesRegex(r.Refusal, 'terminal-state-regression'):
                    api.observe_request_state(old, new, rid)
        changed = copy.deepcopy(complete)
        changed['result'][0]['record']['components'][0]['signature'] = h(9)*2
        with self.assertRaisesRegex(r.Refusal, 'terminal-state-regression'):
            api.observe_request_state(complete, changed, rid)
        with self.assertRaisesRegex(r.Refusal, 'reserved-state-regression'):
            api.observe_request_state(reserved, absent, rid)
        changed = copy.deepcopy(complete)
        changed['statement_id'] = h(9); changed['result'][0]['statement_id'] = h(9)
        with self.assertRaisesRegex(r.Refusal, 'reserved-state-binding'):
            api.observe_request_state(reserved, changed, rid)
        with self.assertRaisesRegex(r.Refusal, 'state-correlation'):
            api.observe_request_state(complete, complete, h(2))


if __name__ == '__main__':
    unittest.main()
