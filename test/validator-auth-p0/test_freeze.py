"""400-member capacity, bounded carriers and consecutive-block recovery gates."""
import copy
import unittest
import reference as r
import transfer as tr
import lifecycle as lc
import api
import test_lifecycle_api as t
from ed25519_oracle import Verifier


class FreezeTests(unittest.TestCase):
    def test_400_limit_and_large_certificate(self):
        duty=t.shape('duty'); pq=dict(suite=2,parameters=1,epoch=1,key_id=t.h(2),signature=bytes(65536))
        classical=dict(suite=1,parameters=1,epoch=1,key_id=t.h(1),signature=bytes(64))
        rows=[dict(identity=(i+1).to_bytes(32,'big'),components=[classical,pq]) for i in range(400)]
        cert=dict(duty=duty,payload=bytes(4096),records=rows)
        raw=r.encode('certificate',cert)
        self.assertEqual(len(raw),26295943)
        with self.assertRaisesRegex(r.Refusal,'list-bound'):
            r.encode('certificate',dict(cert,records=rows+[rows[0]]))
        value=tr.value(raw,4)
        fetched=lambda ref,i: raw[i*tr.CHUNK:(i+1)*tr.CHUNK]
        self.assertEqual(tr.resolve(value,4,fetched),raw)
        frame=tr.tl_wrap(b'1234',raw,4)
        self.assertLess(len(frame),65536)
        self.assertEqual(tr.tl_unwrap(b'1234',frame,4,fetched),raw)
        req=dict(anchor=t.anchor(),certificate=value,committee=t.proof(5,duty['committee']),policy=t.proof(2,duty['policy']))
        self.assertLess(len(api.encode_transport(13,req)),4194304)
        api.validate_request(13,req,fetched)

    def test_worst_committee_capacity(self):
        classical=t.key();pq=dict(classical,suite=2,public_key=bytes(16384))
        keys=[dict(k,role=role) for role in range(1,6) for k in (classical,pq)]
        member=dict(identity=t.h(1),stake_id=t.h(2),weight=1,adnl_id=t.h(3),keys=keys)
        committee=dict(policy=t.h(1),election=t.h(2),workchain=-1,shard=1<<63,catchain=1,anchor_mc=1,members=[member]*400)
        raw=r.encode('committee',committee)
        self.assertEqual(len(raw),33294094)
        self.assertLess(len(raw),r.MAX_OBJECT)
        with self.assertRaisesRegex(r.Refusal,'list-bound'):
            r.encode('committee',dict(committee,members=[member]*401))
        # Membership/identity admission is separate from this maximum-size fixture.

    def test_chunk_rejections_and_bounded_upload(self):
        raw=b'x'*(tr.CHUNK+1);ref=tr.manifest(raw,4)
        tr.validate_manifest(ref)
        for modify,code in [(lambda p:p.update(byte_length=33554433),'manifest-length'),
                            (lambda p:p['chunk_hashes'].pop(),'manifest-count')]:
            bad=copy.deepcopy(ref);modify(bad)
            with self.assertRaisesRegex(r.Refusal,code):tr.validate_manifest(bad)
        for i,part,code in [(2,b'x','chunk-index'),(0,b'x','chunk-length'),(1,b'y','chunk-hash')]:
            with self.assertRaisesRegex(r.Refusal,code):tr.chunk(ref,i,part)
        receiver=tr.Receiver(budget=len(raw))
        mid=receiver.put(ref,0,raw[:tr.CHUNK]);receiver.put(ref,0,raw[:tr.CHUNK])
        self.assertEqual(receiver.reserved,len(raw))
        with self.assertRaisesRegex(r.Refusal,'chunks-missing'):receiver.finish(mid)
        other=tr.manifest(b'y'*len(raw),4)
        with self.assertRaisesRegex(r.Refusal,'transfer-budget'):receiver.put(other,0,b'y'*tr.CHUNK)
        receiver.put(ref,1,raw[tr.CHUNK:]);self.assertEqual(receiver.finish(mid),raw)
        self.assertEqual(receiver.reserved,0)
        bad=copy.deepcopy(ref);bad['object_id']=t.h(7)
        bad['chunk_hashes']=[r.digest('object-chunk',bad['object_id']+bytes([i])+raw[i*tr.CHUNK:(i+1)*tr.CHUNK]) for i in range(2)]
        with self.assertRaisesRegex(r.Refusal,'object-hash'):
            tr.resolve(dict(kind=4,inline=b'',reference=[bad]),4,lambda _,i:raw[i*tr.CHUNK:(i+1)*tr.CHUNK])
        for method in (14,15):
            req=dict(anchor=t.anchor(),manifest=ref,index=0)
            result=dict(anchor=t.anchor(),manifest_id=r.object_id('object_ref',ref),index=0)
            (req if method==15 else result)['data']=raw[:tr.CHUNK]
            api.validate_request(method,req);api.validate_response(method,req,result)
            self.assertEqual(api.decode_transport(api.encode_transport(method,req),method)[1],req)
            result['index']=1
            with self.assertRaisesRegex(r.Refusal,'chunk-correlation'):api.validate_response(method,req,result)

    def test_replay_requires_every_block_and_snapshot_is_read_only(self):
        s,a=t.initial();s,a=t.apply(s,a,t.update(s,a,effective=200),100)
        s,a=t.apply(s,a,t.update(s,a,role=2,effective=210),150)
        checkpoint=dict(coordinate=150,registry_revision=3,identities={s['identity']:s},archive=a)
        with self.assertRaisesRegex(r.Refusal,'block-gap'):
            lc.apply_block(checkpoint,210,[],t.VERIFIERS,lambda _:True)
        with self.assertRaisesRegex(r.Refusal,'snapshot-state-not-current'):
            lc.snapshot(s,a,210,[(1,1,1)])
        def run(state,end):
            for height in range(state['coordinate']+1,end+1):
                state=lc.apply_block(state,height,[],t.VERIFIERS,lambda _:True)
            return state
        direct=run(checkpoint,210)
        segmented=run(copy.deepcopy(run(checkpoint,200)),210)
        self.assertEqual(direct,segmented)
        self.assertEqual(direct['registry_revision'],5)
        current=direct['identities'][s['identity']];before=r.encode('identity',current)
        self.assertEqual(lc.snapshot(current,a,210,[(1,1,1),(2,1,1)])[0]['epoch'],2)
        self.assertEqual(before,r.encode('identity',current))
        u=t.update(current,a,op=3,role=3,effective=220)
        accepted=lc.apply_block(direct,211,[(s['identity'],u,t.evidence(u,current))],t.VERIFIERS,lambda _:True)
        self.assertEqual(accepted['registry_revision'],6)

    def test_service_policy_and_component_separation(self):
        public,_=t.vectors.sign(t.h(1),b'fixture');issuer=r.digest('service-key',public)
        body=t.shape('permit_body');body.update(issuer=issuer,anchor=t.anchor(),expires_mc=110)
        permit=t.service_sign('permit',body);trust=t.service_trust(public)
        expected={k:v for k,v in body.items() if k!='issuer'}
        api.verify_permit(permit,expected,trust,Verifier(),100)
        bad=copy.deepcopy(trust);bad[issuer]['policy_id']=t.h(9)
        with self.assertRaisesRegex(r.Refusal,'service-policy'):api.verify_permit(permit,expected,bad,Verifier(),100)
        bad=copy.deepcopy(permit);bad['components']*=2
        with self.assertRaisesRegex(r.Refusal,'service-components'):api.verify_permit(bad,expected,trust,Verifier(),100)
        bad=copy.deepcopy(permit);bad['components'][0]['key_id']=t.h(9)
        with self.assertRaisesRegex(r.Refusal,'service-components'):api.verify_permit(bad,expected,trust,Verifier(),100)

if __name__=='__main__':unittest.main()
