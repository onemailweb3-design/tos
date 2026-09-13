"""Profile/reference tests; native integration and hardware safety are separate gates."""
import copy
import hashlib
import gzip
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
import reference as r
from ed25519_oracle import Verifier, L, P
import vectors

DOC = vectors.DOC
HERE = Path(__file__).resolve().parent
GOLDEN = json.loads(gzip.decompress((HERE/'golden.json.gz').read_bytes()))
POLICY = r.decode('policy',bytes.fromhex(GOLDEN['policy']))
COMMITTEE = r.decode('committee',bytes.fromhex(GOLDEN['committee']))
CERTS = [r.decode('certificate',bytes.fromhex(c['certificate'])) for c in GOLDEN['cases']]

class ProfileTests(unittest.TestCase):
    def verify(self, cert, committee=None, policy=None, expected=None, verifier=None):
        return r.verify_c0(cert, COMMITTEE if committee is None else committee,
                           POLICY if policy is None else policy, CERTS[0]['duty'] if expected is None else expected,
                           Verifier() if verifier is None else verifier)

    def test_frozen_vectors_and_independent_crypto(self):
        self.assertEqual(vectors.build(),GOLDEN)
        self.assertEqual(POLICY['interface_digest'],hashlib.sha256((DOC/'profile.json').read_bytes()).digest())
        for cert, case in zip(CERTS,GOLDEN['cases']):
            with self.subTest(role=case['role']):
                self.assertEqual(self.verify(cert,expected=cert['duty']),3)
                self.assertEqual(r.statement(cert['duty'],cert['records'][0]).hex(),case['statement'])
                self.assertEqual(r.encode('envelope',dict(duty=cert['duty'],payload=cert['payload'],record=cert['records'][0])).hex(),case['envelope'])
                self.assertEqual(r.encode('certificate',cert).hex(),case['certificate'])

    def test_headers_truncation_and_tail(self):
        raw = bytes.fromhex(GOLDEN['cases'][0]['certificate'])
        for n in range(len(raw)):
            with self.subTest(prefix=n),self.assertRaises(r.Refusal):
                r.decode('certificate',raw[:n])
        for position,value in ((0,0),(5,2),(7,1)):
            bad=bytearray(raw);bad[position]=value
            with self.subTest(position=position),self.assertRaises(r.Refusal):
                r.decode('certificate',bytes(bad))
        with self.assertRaisesRegex(r.Refusal,'trailing'):
            r.decode('certificate',raw+b'\0')

    def test_object_roundtrips(self):
        samples = {'key':COMMITTEE['members'][0]['keys'][0], 'policy':POLICY,'committee':COMMITTEE,
                   'duty':CERTS[0]['duty'],'update':r.decode('update',CERTS[4]['payload']),
                   'identity':dict(identity=vectors.h(11),stake_id=vectors.h(21),owner_workchain=-1,owner_address=vectors.h(71),
                                   next_nonce=1,previous=bytes(32),active=[],pending=[]),
                   'activation':dict(revision=2,previous=vectors.h(80),next_policy=vectors.h(81),effective_from=200,
                                     checkpoint_seqno=150,checkpoint_root=vectors.h(82),checkpoint_file=vectors.h(83),checkpoint_state=vectors.h(84)),
                   'observation':dict(suite=2,parameters=1,registry_root=vectors.h(85),valid_from=200,valid_until=300,enabled=0)}
        for kind,obj in samples.items():
            with self.subTest(kind=kind):
                self.assertEqual(r.decode(kind,r.encode(kind,obj)),obj)

    def test_integer_and_resource_limits(self):
        for bad in (-1,65536,True):
            with self.subTest(value=bad),self.assertRaises(r.Refusal):
                r.encode('suite',dict(suite=bad,parameters=1))
        component=copy.deepcopy(CERTS[0]['records'][0]['components'][0])
        component['signature']=bytes(65536)
        raw=r.encode('component',component)
        self.assertEqual(r.decode('component',raw),component)
        # A large structural fixture is not a cryptographically valid PQ signature.
        with self.assertRaisesRegex(r.Refusal,'blob-bound'):
            r.decode('component',raw[:44]+struct.pack('>I',65537))
        with self.assertRaisesRegex(r.Refusal,'list-bound'):
            r.decode('record',vectors.h(11)+b'\x03')
        with self.assertRaisesRegex(r.Refusal,'object-bound'):
            r.decode('certificate',bytes(r.MAX_OBJECT+1))

    def test_c0_does_not_enable_reserved_profiles(self):
        for phase in (1,2,3,255):
            p=copy.deepcopy(POLICY);p['phase']=phase
            with self.subTest(phase=phase),self.assertRaisesRegex(r.Refusal,'c0-policy'):
                r.validate_c0_policy(p)
        for suite,parameters in ((0,0),(2,44),(32768,1),(1,2)):
            p=copy.deepcopy(POLICY);p['suites']=[dict(suite=suite,parameters=parameters)]
            with self.subTest(suite=suite,parameters=parameters),self.assertRaisesRegex(r.Refusal,'c0-policy'):
                r.validate_c0_policy(p)
        cert=copy.deepcopy(CERTS[0]);cert['records'][0]['components']*=2
        with self.assertRaisesRegex(r.Refusal,'c0-components'):
            self.verify(cert)

    def test_all_context_fields_are_independently_expected(self):
        for field,value in CERTS[0]['duty'].items():
            expected=copy.deepcopy(CERTS[0]['duty'])
            expected[field]=(bytes([value[0]^1])+value[1:]) if isinstance(value,bytes) else value+1
            with self.subTest(field=field),self.assertRaisesRegex(r.Refusal,'expected-context'):
                self.verify(CERTS[0],expected=expected)

    def test_key_reference_and_admission_before_signature(self):
        class Counter(Verifier):
            calls=0
            def verify(self,*args):
                self.calls+=1
                return super().verify(*args)
        for field in ('suite','parameters','epoch','key_id'):
            cert=copy.deepcopy(CERTS[0]);c=cert['records'][0]['components'][0]
            c[field]=vectors.h(99) if field=='key_id' else c[field]+1
            provider=Counter()
            with self.subTest(field=field),self.assertRaisesRegex(r.Refusal,'key-binding'):
                self.verify(cert,verifier=provider)
            self.assertEqual(provider.calls,0)
        for size in (0,63,65,2420):
            cert=copy.deepcopy(CERTS[0]);cert['records'][0]['components'][0]['signature']=bytes(size)
            provider=Counter()
            with self.subTest(size=size),self.assertRaisesRegex(r.Refusal,'signature-size'):
                self.verify(cert,verifier=provider)
            self.assertEqual(provider.calls,0)

    def test_registry_semantics_and_commitment(self):
        for kind in ('zero-weight','overflow','duplicate-stake','missing-role','expired','capacity','bad-public-key','replace-absent'):
            committee=copy.deepcopy(COMMITTEE);member=committee['members'][0]
            if kind=='zero-weight':member['weight']=0
            if kind=='overflow':member['weight']=r.MAX_WEIGHT
            if kind=='duplicate-stake':member['stake_id']=committee['members'][1]['stake_id']
            if kind=='missing-role':member['keys'].pop()
            if kind=='expired':member['keys'][0]['valid_until']=100
            if kind=='capacity':member['keys'][0]['capacity_limit']=1
            if kind=='bad-public-key':member['keys'][0]['public_key']=b'\1'+bytes(31)
            if kind=='replace-absent':committee['members'][2]['adnl_id']=vectors.h(99)
            cert=copy.deepcopy(CERTS[0]);cert['records']=cert['records'][:2]
            with self.subTest(kind=kind),self.assertRaises(r.Refusal):
                self.verify(cert,committee=committee)

    def test_quorum_and_surplus_invalid_signature(self):
        cert=copy.deepcopy(CERTS[0]);cert['records']=cert['records'][:2]
        try:
            actual=self.verify(cert)
        except r.Refusal as exc:
            self.fail('exact two-of-three quorum rejected: '+str(exc))
        self.assertEqual(actual,2)
        cert['records']=cert['records'][:1]
        with self.assertRaisesRegex(r.Refusal,'quorum'):
            self.verify(cert)
        cert=copy.deepcopy(CERTS[0]);c=cert['records'][2]['components'][0]
        c['signature']=bytes([c['signature'][0]^1])+c['signature'][1:]
        with self.assertRaisesRegex(r.Refusal,'signature'):
            self.verify(cert)

    def test_signer_uniqueness_order_and_membership(self):
        for mode in ('duplicate','reverse','unknown','empty'):
            cert=copy.deepcopy(CERTS[0])
            if mode=='duplicate':cert['records'][1]=copy.deepcopy(cert['records'][0])
            if mode=='reverse':cert['records'].reverse()
            if mode=='unknown':cert['records'][-1]['identity']=vectors.h(99)
            if mode=='empty':cert['records']=[]
            with self.subTest(mode=mode),self.assertRaises(r.Refusal):
                self.verify(cert)

    def test_payload_constructor_and_position(self):
        for role in range(1,5):
            cert=copy.deepcopy(CERTS[role-1]);d=cert['duty']
            payload=bytes([cert['payload'][0]^1])+cert['payload'][1:]
            d['payload_hash']=r.digest('payload',bytes([role])+payload)
            with self.subTest(role=role),self.assertRaisesRegex(r.Refusal,'payload-type'):
                r.validate_payload(d,payload)
            d=copy.deepcopy(CERTS[role-1]['duty']);d['position']+=1
            with self.subTest(role=role),self.assertRaisesRegex(r.Refusal,'payload-position'):
                r.validate_payload(d,CERTS[role-1]['payload'])

    def test_ed25519_canonicality(self):
        provider=Verifier();cert=CERTS[0];row=cert['records'][0]
        message=r.statement(cert['duty'],row);key=COMMITTEE['members'][0]['keys'][0]['public_key']
        signature=row['components'][0]['signature']
        self.assertTrue(provider.verify(key,message,signature))
        self.assertFalse(provider.verify(key,message+b'x',signature))
        self.assertFalse(provider.verify(key,message,signature[:32]+L.to_bytes(32,'little')))
        self.assertFalse(provider.verify(key,message,P.to_bytes(32,'little')+signature[32:]))
        for key in (bytes(32),b'\1'+bytes(31),P.to_bytes(32,'little'),(1+(1<<255)).to_bytes(32,'little')):
            self.assertFalse(provider.admit(key))

    def test_tl_bytes_canonicality(self):
        tag=bytes.fromhex('f6bb924b')
        for size in (0,1,253,254,255,1024,65536):
            raw=bytes([42])*size
            with self.subTest(size=size):
                self.assertEqual(r.tl_unframe(tag,r.tl_frame(tag,raw)),raw)
        for bad in (tag+b'\xff\0\0\0',tag+b'\xfe\x01\0\0x\0\0\0',tag+b'\x01x\0\x01',r.tl_frame(tag,b'x')+b'\0'):
            with self.assertRaises(r.Refusal):r.tl_unframe(tag,bad)

    def test_canonical_tree_is_not_a_boc_test(self):
        for size in (1,120,121,480,481,1920,1921,65536):
            raw=bytes([42])*size
            self.assertEqual(r.unbyte_tree(r.byte_tree(raw)),raw)
        for bad in ((0,b''),(1,121,[(0,b'x'*120)]),(1,121,[(0,b'x'*119),(0,b'xx')]),
                    (1,122,[(0,b'x'*120),(0,b'x')])):
            with self.assertRaises(r.Refusal):r.unbyte_tree(bad)

    def test_real_consensus_conflict_table_model(self):
        for roles in ((2,4),(4,2),(2,3),(3,2)):
            state={}
            self.assertTrue(r.reserve_vote(state,roles[0],b'A'))
            self.assertTrue(r.reserve_vote(state,roles[1],b'A'))
            self.assertFalse(r.reserve_vote(state,roles[1],b'A'))
        for roles,payloads in (((3,4),(b'A',b'A')),((4,3),(b'A',b'A')),((2,3),(b'A',b'B')),((3,2),(b'A',b'B')),((2,2),(b'A',b'B'))):
            state={};r.reserve_vote(state,roles[0],payloads[0])
            with self.assertRaisesRegex(r.Refusal,'conflict'):r.reserve_vote(state,roles[1],payloads[1])

    def test_policy_selection_is_by_session_birth(self):
        newer=copy.deepcopy(POLICY);newer.update(revision=2,previous=r.object_id('policy',POLICY),effective_from=200)
        history=[POLICY,newer]
        for anchor,expected in ((0,1),(199,1),(200,2),(201,2)):
            self.assertEqual(r.select_policy(history,anchor)['revision'],expected)
        for field,value in (('revision',3),('previous',bytes(32)),('effective_from',0)):
            bad=copy.deepcopy(newer);bad[field]=value
            with self.subTest(field=field),self.assertRaises(r.Refusal):r.select_policy([POLICY,bad],200)

    def test_sql_real_reopen_and_non_reusable_reservations(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'store.sqlite';db=sqlite3.connect(path,isolation_level=None)
            db.executescript((DOC/'signer-store.sql').read_text())
            kid=r.object_id('key',COMMITTEE['members'][0]['keys'][0]);did=vectors.h(90)
            db.execute('INSERT INTO key_versions VALUES (?,?)',(kid,b'public descriptor'))
            values=(did,vectors.h(11),vectors.h(20),-1,(1<<63).to_bytes(8,'big'),(8).to_bytes(8,'big'),2,vectors.h(91),bytes(8),'RESERVED',None)
            db.execute('BEGIN IMMEDIATE');db.execute('INSERT INTO duties VALUES (?,?,?,?,?,?,?,?,?,?,?)',values)
            db.execute('INSERT INTO capacity_reservations VALUES (?,?,?)',(vectors.h(92),bytes(8),did));db.execute('COMMIT');db.close()
            db=sqlite3.connect(path,isolation_level=None);db.execute('PRAGMA foreign_keys=ON')
            self.assertEqual(db.execute('SELECT state FROM duties').fetchone()[0],'RESERVED')
            for sql,args in (('INSERT INTO duties VALUES (?,?,?,?,?,?,?,?,?,?,?)',values),
                             ('UPDATE key_versions SET descriptor=?',(b'changed',)),('DELETE FROM key_versions',()),
                             ('INSERT INTO capacity_reservations VALUES (?,?,?)',(vectors.h(92),bytes(8),did)),
                             ('DELETE FROM capacity_reservations',()),('UPDATE duties SET statement_id=?',(vectors.h(99),))):
                with self.subTest(sql=sql),self.assertRaises(sqlite3.IntegrityError):db.execute(sql,args)
            db.execute("UPDATE duties SET state='COMPLETE',result=?",(b'exact signature',));db.close()
            db=sqlite3.connect(path,isolation_level=None)
            self.assertEqual(db.execute('SELECT result FROM duties').fetchone()[0],b'exact signature')
            with self.assertRaises(sqlite3.IntegrityError):db.execute("UPDATE duties SET state='RESERVED',result=NULL")
            with self.assertRaises(sqlite3.IntegrityError):db.execute('DELETE FROM duties')
            db.close()

if __name__ == '__main__':
    unittest.main()
